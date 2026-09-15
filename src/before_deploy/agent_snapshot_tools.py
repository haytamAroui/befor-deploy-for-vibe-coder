"""Read-only agent tools over exact materialized advisory-context snapshots."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from before_deploy.advisory_context import AdvisoryContextFile
from before_deploy.agent_runtime import AgentToolRequest, AgentToolResult
from before_deploy.agent_tools import RepositoryToolPolicy

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


class SnapshotRepositoryTools:
    """Execute the standard repository tool vocabulary against selected snapshot files only."""

    def __init__(
        self,
        files: Sequence[AdvisoryContextFile],
        *,
        policy: RepositoryToolPolicy | None = None,
    ) -> None:
        self.policy = policy or RepositoryToolPolicy(allow_scope_expansion=False)
        self.policy.validate()
        self._files = {item.path: tuple(item.content.splitlines()) for item in files}
        if len(self._files) != len(files):
            raise ValueError("Historical agent snapshot paths must be unique")

    def execute(self, request: AgentToolRequest, *, max_bytes: int) -> AgentToolResult:
        if request.tool_name not in self.policy.allowed_tools:
            return self._result(request, "DENIED", {"error": "tool_not_allowed"}, max_bytes)
        try:
            payload = self._dispatch(request.tool_name, request.arguments)
            return self._result(request, "OK", payload, max_bytes)
        except ValueError as error:
            return self._result(request, "DENIED", {"error": str(error)}, max_bytes)

    def _dispatch(self, name: str, args: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(args, Mapping):
            raise ValueError("arguments_must_be_object")
        if name == "read_file":
            return self._read_file(args)
        if name == "search_text":
            return self._search_text(args)
        if name == "search_symbol":
            return self._search_symbol(args)
        if name == "find_references":
            return self._references(args, calls_only=False, tests_only=False)
        if name == "find_callers":
            return self._references(args, calls_only=True, tests_only=False)
        if name == "find_tests":
            return self._references(args, calls_only=False, tests_only=True)
        if name == "dependency_neighbors":
            return self._dependency_neighbors(args)
        raise ValueError("unsupported_tool")

    def _read_file(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        path = self._path(args)
        lines = self._files[path]
        start = _positive(args.get("start_line", 1), "start_line")
        default_end = min(len(lines), start + self.policy.max_read_lines - 1)
        if not lines:
            return {"path": path, "line_count": 0, "start_line": None, "end_line": None, "lines": []}
        end = _positive(args.get("end_line", default_end), "end_line")
        if start > len(lines) or end < start:
            raise ValueError("invalid_line_range")
        end = min(end, start + self.policy.max_read_lines - 1, len(lines))
        return {
            "path": path,
            "line_count": len(lines),
            "start_line": start,
            "end_line": end,
            "lines": [{"line": i, "text": lines[i - 1]} for i in range(start, end + 1)],
        }

    def _search_text(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        query = _text(args, "query", 300)
        terms = tuple(sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", query.lower()))))
        terms = terms or (query.lower(),)
        matches = []
        for path, lines in sorted(self._files.items()):
            for line_number, text in enumerate(lines, start=1):
                hits = sum(term in text.lower() for term in terms)
                if hits:
                    matches.append((-hits, path, line_number, text.strip()))
        matches.sort()
        limited = matches[: self.policy.max_results]
        return {
            "query": query,
            "matches": [
                {"path": path, "line": line, "text": text, "term_hits": -score}
                for score, path, line, text in limited
            ],
            "truncated": len(matches) > len(limited),
            "semantics": "snapshot_lexical_search",
        }

    def _search_symbol(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        symbol = _symbol(args)
        matches = []
        for path, lines in sorted(self._files.items()):
            for line_number, text in enumerate(lines, start=1):
                if _definition_name(text) == symbol:
                    matches.append({"path": path, "line": line_number, "text": text.strip()})
        return {"symbol": symbol, "definitions": matches[: self.policy.max_results], "truncated": len(matches) > self.policy.max_results}

    def _references(self, args: Mapping[str, Any], *, calls_only: bool, tests_only: bool) -> Mapping[str, Any]:
        symbol = _symbol(args)
        pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(" if calls_only else rf"\b{re.escape(symbol)}\b")
        matches = []
        for path, lines in sorted(self._files.items()):
            if tests_only and not _is_test_path(path):
                continue
            for line_number, text in enumerate(lines, start=1):
                if pattern.search(text):
                    if calls_only and _definition_name(text) == symbol:
                        continue
                    matches.append({"path": path, "line": line_number, "text": text.strip()})
        key = "call_sites" if calls_only else "test_references" if tests_only else "references"
        return {"symbol": symbol, key: matches[: self.policy.max_results], "truncated": len(matches) > self.policy.max_results, "semantics": "snapshot_lexical_reference"}

    def _dependency_neighbors(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        path = self._path(args)
        imports = _dependencies(self._files[path])
        names = _module_names(path)
        importers = []
        for candidate, lines in sorted(self._files.items()):
            if candidate == path:
                continue
            if any(_dep_matches(dep, names) for dep in _dependencies(lines)):
                importers.append(candidate)
        return {"path": path, "imports": list(imports), "possible_importers": importers[: self.policy.max_results], "truncated": len(importers) > self.policy.max_results, "semantics": "snapshot_static_import_neighbors"}

    def _path(self, args: Mapping[str, Any]) -> str:
        path = _canonical_path(_text(args, "path", 500))
        if path not in self._files:
            raise ValueError("path_outside_exact_snapshot")
        return path

    @staticmethod
    def _result(request: AgentToolRequest, status: str, payload: Mapping[str, Any], max_bytes: int) -> AgentToolResult:
        content = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        encoded = content.encode("utf-8")
        truncated = False
        if len(encoded) > max_bytes:
            content = json.dumps({"truncated": True, "original_sha256": sha256(encoded).hexdigest(), "original_size_bytes": len(encoded)}, sort_keys=True, separators=(",", ":"))
            if len(content.encode("utf-8")) > max_bytes:
                raise ValueError("tool_result_bound_too_small")
            truncated = True
        return AgentToolResult.from_text(call_id=request.call_id, tool_name=request.tool_name, status=status, content=content, truncated=truncated, message=None if status == "OK" else str(payload.get("error", status)))


def _definition_name(text: str) -> str | None:
    for pattern in _SYMBOL_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _dependencies(lines: Sequence[str]) -> tuple[str, ...]:
    values = set()
    for text in lines:
        for pattern in _IMPORT_PATTERNS:
            match = pattern.search(text)
            if match:
                values.add(match.group(1))
                break
    return tuple(sorted(values))


def _text(args: Mapping[str, Any], name: str, max_chars: int) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name}_required")
    value = value.strip()
    if len(value) > max_chars:
        raise ValueError(f"{name}_too_long")
    return value


def _symbol(args: Mapping[str, Any]) -> str:
    value = _text(args, "symbol", 200)
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.:]*", value):
        raise ValueError("symbol_invalid")
    return value.split(".")[-1].split("::")[-1]


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name}_must_be_positive")
    return value


def _canonical_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise ValueError("path_must_be_repository_relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("path_must_be_repository_relative")
    return path.as_posix()


def _is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    return any(part in {"test", "tests", "spec", "specs"} for part in parts) or name.startswith("test_") or ".test." in name or ".spec." in name or name.endswith("_test.go") or name.endswith("test.java")


def _module_names(path: str) -> frozenset[str]:
    pure = PurePosixPath(path)
    base = pure.with_suffix("").as_posix()
    return frozenset({base, base.replace("/", "."), pure.stem})


def _dep_matches(dependency: str, names: frozenset[str]) -> bool:
    normalized = dependency.replace("::", ".").replace("/", ".")
    return any(normalized == name.replace("/", ".") or normalized.endswith("." + name.replace("/", ".")) for name in names)
