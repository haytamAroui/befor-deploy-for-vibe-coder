"""Bounded deterministic repository index used by advisory agent tools."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from before_deploy.inventory import collect_inventory

_SYMBOL_PATTERNS = (
    re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b"),
    re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\b"),
)
_IMPORT_PATTERNS = (
    re.compile(r"^\s*from\s+([A-Za-z0-9_.]+)\s+import\b"),
    re.compile(r"^\s*import\s+([A-Za-z0-9_.]+)\b"),
    re.compile(r"^\s*import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]"),
    re.compile(r"^\s*use\s+([A-Za-z0-9_:]+)"),
)


@dataclass(frozen=True)
class RepositoryIndexPolicy:
    max_file_bytes: int = 1_000_000
    max_files: int = 5_000
    max_total_bytes: int = 32_000_000

    def validate(self) -> None:
        for name, value in self.__dict__.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"Repository index {name} must be positive")


@dataclass(frozen=True)
class IndexedFile:
    path: str
    lines: tuple[str, ...]
    symbols: tuple[tuple[str, int], ...]
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class RepositoryIndex:
    root: Path
    files: Mapping[str, IndexedFile]
    indexed_bytes: int
    skipped_count: int

    @classmethod
    def build(
        cls,
        repository: Path,
        *,
        policy: RepositoryIndexPolicy | None = None,
    ) -> "RepositoryIndex":
        bounds = policy or RepositoryIndexPolicy()
        bounds.validate()
        inventory = collect_inventory(repository, max_file_bytes=bounds.max_file_bytes)
        indexed: dict[str, IndexedFile] = {}
        indexed_bytes = 0
        skipped_count = 0
        for source_path in inventory.files:
            if len(indexed) >= bounds.max_files:
                skipped_count += 1
                continue
            path = source_path.relative_to(inventory.root).as_posix()
            if path_has_symlink(inventory.root, path):
                skipped_count += 1
                continue
            try:
                raw = source_path.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                skipped_count += 1
                continue
            if indexed_bytes + len(raw) > bounds.max_total_bytes:
                skipped_count += 1
                continue
            lines = tuple(text.splitlines())
            indexed[path] = IndexedFile(
                path=path,
                lines=lines,
                symbols=_symbols(lines),
                dependencies=_dependencies(lines),
            )
            indexed_bytes += len(raw)
        return cls(
            root=inventory.root,
            files=indexed,
            indexed_bytes=indexed_bytes,
            skipped_count=skipped_count,
        )

    def definitions(self, symbol: str) -> tuple[tuple[str, int, str], ...]:
        matches = []
        for item in self.files.values():
            for name, line in item.symbols:
                if name == symbol:
                    matches.append((item.path, line, item.lines[line - 1].strip()))
        return tuple(sorted(matches))

    def references(
        self,
        symbol: str,
        *,
        calls_only: bool = False,
        tests_only: bool = False,
    ) -> tuple[tuple[str, int, str], ...]:
        word = re.compile(rf"\b{re.escape(symbol)}\b")
        call = re.compile(rf"\b{re.escape(symbol)}\s*\(")
        matches = []
        for item in self.files.values():
            if tests_only and not is_test_path(item.path):
                continue
            for line_number, text in enumerate(item.lines, start=1):
                pattern = call if calls_only else word
                if not pattern.search(text):
                    continue
                if calls_only and (symbol, line_number) in item.symbols:
                    continue
                matches.append((item.path, line_number, text.strip()))
        return tuple(sorted(matches))

    def lexical_search(self, query: str) -> tuple[tuple[int, str, int, str], ...]:
        terms = tuple(sorted(set(_query_terms(query))))
        if not terms:
            terms = (query.lower(),)
        matches = []
        for item in self.files.values():
            for line_number, text in enumerate(item.lines, start=1):
                lowered = text.lower()
                score = sum(term in lowered for term in terms)
                if score:
                    matches.append((-score, item.path, line_number, text.strip()))
        return tuple(sorted(matches))

    def dependency_neighbors(self, path: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        item = self.files[path]
        names = module_names(path)
        importers = []
        for candidate in self.files.values():
            if candidate.path == path:
                continue
            if any(dependency_matches(dependency, names) for dependency in candidate.dependencies):
                importers.append(candidate.path)
        return item.dependencies, tuple(sorted(importers))


def canonical_repository_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("path_required")
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("path_must_be_repository_relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("path_must_be_repository_relative")
    if any(part in {"", "."} for part in candidate.parts):
        raise ValueError("path_must_be_canonical")
    return candidate.as_posix()


def path_has_symlink(root: Path, path: str) -> bool:
    current = root
    for part in PurePosixPath(path).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    return (
        any(part in {"test", "tests", "spec", "specs"} for part in parts)
        or name.startswith("test_")
        or ".test." in name
        or ".spec." in name
        or name.endswith("_test.go")
        or name.endswith("test.java")
    )


def module_names(path: str) -> frozenset[str]:
    pure = PurePosixPath(path)
    base = pure.with_suffix("").as_posix()
    return frozenset({base, base.replace("/", "."), pure.stem})


def dependency_matches(dependency: str, names: frozenset[str]) -> bool:
    normalized = dependency.replace("::", ".").replace("/", ".")
    return any(
        normalized == name.replace("/", ".")
        or normalized.endswith("." + name.replace("/", "."))
        for name in names
    )


def _symbols(lines: Sequence[str]) -> tuple[tuple[str, int], ...]:
    values = []
    for line_number, text in enumerate(lines, start=1):
        for pattern in _SYMBOL_PATTERNS:
            match = pattern.search(text)
            if match:
                values.append((match.group(1), line_number))
                break
    return tuple(values)


def _dependencies(lines: Sequence[str]) -> tuple[str, ...]:
    values = set()
    for text in lines:
        for pattern in _IMPORT_PATTERNS:
            match = pattern.search(text)
            if match:
                values.add(match.group(1))
                break
    return tuple(sorted(values))


def _query_terms(query: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", query.lower()))
