"""Validation for versioned, provenance-backed review benchmark corpora."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
from json import loads
from pathlib import Path, PurePosixPath
from re import fullmatch
from subprocess import CompletedProcess, run
from typing import Any, Mapping

from before_deploy.review_benchmark import BenchmarkCorpus, load_benchmark_corpus

CORPUS_MANIFEST_SCHEMA_VERSION = 1
CANONICAL_ADVISORY_CATEGORIES = frozenset(
    {
        "bug",
        "security",
        "performance",
        "maintainability",
        "test",
        "style",
        "documentation",
        "other",
    }
)
CANONICAL_ADVISORY_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_SOURCE_ROLES = frozenset({"positive", "negative"})


@dataclass(frozen=True)
class BenchmarkCorpusValidation:
    """Summary of a successful corpus provenance validation."""

    name: str
    source_repository: str
    source_commit: str
    positive_file_count: int
    negative_file_count: int
    defect_count: int


def validate_benchmark_corpus_provenance(
    corpus_path: Path,
    manifest_path: Path,
    repository_root: Path,
) -> BenchmarkCorpusValidation:
    """Validate labels, byte-level source provenance, and regression-test references."""
    root = repository_root.resolve()
    resolved_corpus = _resolve_input(corpus_path, root)
    resolved_manifest = _resolve_input(manifest_path, root)
    corpus = load_benchmark_corpus(resolved_corpus)
    manifest = _load_mapping(resolved_manifest, "benchmark corpus manifest")

    if manifest.get("schema_version") != CORPUS_MANIFEST_SCHEMA_VERSION:
        raise ValueError("Unsupported benchmark corpus manifest schema")
    manifest_name = _required_text(manifest, "name")
    if manifest_name != corpus.name:
        raise ValueError("Benchmark corpus manifest name does not match corpus name")

    declared_corpus = _safe_relative_path(_required_text(manifest, "corpus"))
    if _resolve_under_root(root, declared_corpus) != resolved_corpus:
        raise ValueError("Benchmark corpus manifest points at a different corpus file")

    snapshot = _required_mapping(manifest, "source_snapshot")
    source_repository = _required_text(snapshot, "repository")
    source_commit = _required_text(snapshot, "commit").lower()
    if fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("Benchmark source snapshot commit must be a full 40-character Git SHA")

    labeling_rules = _safe_relative_path(_required_text(manifest, "labeling_rules"))
    if not _resolve_under_root(root, labeling_rules).is_file():
        raise ValueError("Benchmark labeling rules file does not exist")

    source_roles, source_blobs = _validate_source_files(manifest, root)
    _validate_source_snapshot_membership(root, source_commit, source_blobs)
    _validate_canonical_taxonomy(corpus)
    _validate_label_provenance(manifest, corpus, source_roles, root)

    positive_count = sum(role == "positive" for role in source_roles.values())
    negative_count = sum(role == "negative" for role in source_roles.values())
    return BenchmarkCorpusValidation(
        name=corpus.name,
        source_repository=source_repository,
        source_commit=source_commit,
        positive_file_count=positive_count,
        negative_file_count=negative_count,
        defect_count=len(corpus.defects),
    )


def git_blob_sha1(content: bytes) -> str:
    """Return the Git blob object ID for exact bytes; this is a drift check, not a trust primitive."""
    header = f"blob {len(content)}\0".encode("ascii")
    return sha1(header + content, usedforsecurity=False).hexdigest()


def _validate_source_files(
    manifest: Mapping[str, Any], root: Path
) -> tuple[dict[str, str], dict[str, str]]:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("Benchmark corpus manifest files must be a non-empty array")

    source_roles: dict[str, str] = {}
    source_blobs: dict[str, str] = {}
    for index, raw in enumerate(raw_files):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Benchmark source file {index + 1} must be an object")
        path = _safe_relative_path(_required_text(raw, "path"))
        if path in source_roles:
            raise ValueError(f"Duplicate benchmark source path: {path}")
        role = _required_text(raw, "role").lower()
        if role not in _SOURCE_ROLES:
            raise ValueError(f"Benchmark source path {path} has unsupported role: {role}")
        expected_blob = _required_text(raw, "git_blob_sha1").lower()
        if fullmatch(r"[0-9a-f]{40}", expected_blob) is None:
            raise ValueError(f"Benchmark source path {path} has invalid Git blob SHA-1")
        source_path = _resolve_under_root(root, path)
        if not source_path.is_file():
            raise ValueError(f"Benchmark source path does not exist: {path}")
        actual_blob = git_blob_sha1(source_path.read_bytes())
        if actual_blob != expected_blob:
            raise ValueError(
                f"Git blob hash mismatch for benchmark source {path}: "
                f"expected {expected_blob}, got {actual_blob}"
            )
        source_roles[path] = role
        source_blobs[path] = expected_blob
    return source_roles, source_blobs


def _validate_source_snapshot_membership(
    root: Path,
    source_commit: str,
    source_blobs: Mapping[str, str],
) -> None:
    commit_check = _run_git(root, "cat-file", "-e", f"{source_commit}^{{commit}}")
    if commit_check.returncode != 0:
        raise ValueError(
            "Benchmark source snapshot commit is unavailable in local Git history: "
            f"{source_commit}"
        )

    for path, expected_blob in source_blobs.items():
        tree_entry = _run_git(root, "ls-tree", "-z", "--full-tree", source_commit, "--", path)
        if tree_entry.returncode != 0:
            raise ValueError(
                f"Unable to resolve benchmark source {path} at snapshot commit {source_commit}"
            )
        entries = [entry for entry in tree_entry.stdout.split(b"\0") if entry]
        if len(entries) != 1:
            raise ValueError(
                f"Benchmark source path is absent or ambiguous at snapshot commit: {path}"
            )
        metadata, separator, _ = entries[0].partition(b"\t")
        fields = metadata.decode("ascii", errors="strict").split()
        if not separator or len(fields) != 3 or fields[1] != "blob":
            raise ValueError(f"Benchmark source path is not a file at snapshot commit: {path}")
        snapshot_blob = fields[2].lower()
        if snapshot_blob != expected_blob:
            raise ValueError(
                f"Snapshot blob mismatch for benchmark source {path}: "
                f"commit {source_commit} has {snapshot_blob}, manifest declares {expected_blob}"
            )


def _run_git(root: Path, *arguments: str) -> CompletedProcess[bytes]:
    try:
        return run(
            ["git", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise ValueError("Git is required to validate benchmark source snapshot provenance") from error


def _validate_canonical_taxonomy(corpus: BenchmarkCorpus) -> None:
    for defect in corpus.defects:
        if defect.category not in CANONICAL_ADVISORY_CATEGORIES:
            raise ValueError(
                f"Benchmark defect {defect.defect_id} uses unsupported advisory category: "
                f"{defect.category}"
            )
        if defect.severity is not None and defect.severity not in CANONICAL_ADVISORY_SEVERITIES:
            raise ValueError(
                f"Benchmark defect {defect.defect_id} uses unsupported advisory severity: "
                f"{defect.severity}"
            )


def _validate_label_provenance(
    manifest: Mapping[str, Any],
    corpus: BenchmarkCorpus,
    source_roles: Mapping[str, str],
    root: Path,
) -> None:
    raw_labels = manifest.get("labels")
    if not isinstance(raw_labels, list):
        raise ValueError("Benchmark corpus manifest labels must be an array")

    corpus_by_id = {defect.defect_id: defect for defect in corpus.defects}
    seen_ids: set[str] = set()
    defect_paths: set[str] = set()
    for index, raw in enumerate(raw_labels):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Benchmark provenance label {index + 1} must be an object")
        defect_id = _required_text(raw, "id")
        if defect_id in seen_ids:
            raise ValueError(f"Duplicate benchmark provenance label id: {defect_id}")
        seen_ids.add(defect_id)
        defect = corpus_by_id.get(defect_id)
        if defect is None:
            raise ValueError(f"Benchmark provenance label has no corpus defect: {defect_id}")

        path = _safe_relative_path(_required_text(raw, "path"))
        start_line = _positive_int(raw.get("start_line"), "start_line")
        end_line = _positive_int(raw.get("end_line", start_line), "end_line")
        category = _required_text(raw, "category").lower()
        severity = _optional_text(raw.get("severity"))
        normalized_severity = severity.lower() if severity else None
        if (
            path,
            start_line,
            end_line,
            category,
            normalized_severity,
        ) != (
            defect.path,
            defect.start_line,
            defect.end_line,
            defect.category,
            defect.severity,
        ):
            raise ValueError(f"Benchmark provenance label does not match corpus defect: {defect_id}")
        if source_roles.get(path) != "positive":
            raise ValueError(f"Benchmark defect must reference a positive source file: {defect_id}")
        defect_paths.add(path)

        _required_text(raw, "control_id")
        evidence_test = _required_text(raw, "evidence_test")
        _required_text(raw, "rationale")
        _validate_evidence_test(root, evidence_test)

    missing_labels = sorted(set(corpus_by_id) - seen_ids)
    if missing_labels:
        raise ValueError("Benchmark defects missing provenance labels: " + ", ".join(missing_labels))

    positive_paths = {path for path, role in source_roles.items() if role == "positive"}
    if positive_paths != defect_paths:
        missing_defects = sorted(positive_paths - defect_paths)
        undeclared_positive = sorted(defect_paths - positive_paths)
        detail = []
        if missing_defects:
            detail.append("positive files without defects=" + ",".join(missing_defects))
        if undeclared_positive:
            detail.append("defect files not positive=" + ",".join(undeclared_positive))
        raise ValueError("Benchmark positive-source contract mismatch: " + "; ".join(detail))


def _validate_evidence_test(root: Path, evidence_test: str) -> None:
    test_path_text, separator, selector = evidence_test.partition("::")
    if not separator or fullmatch(r"test_[A-Za-z0-9_]+", selector) is None:
        raise ValueError(f"Benchmark evidence_test must identify one test function: {evidence_test}")
    test_path = _safe_relative_path(test_path_text)
    resolved = _resolve_under_root(root, test_path)
    if not resolved.is_file():
        raise ValueError(f"Benchmark evidence test file does not exist: {test_path}")
    source = resolved.read_text(encoding="utf-8")
    if f"def {selector}(" not in source:
        raise ValueError(f"Benchmark evidence test selector does not exist: {evidence_test}")


def _load_mapping(path: Path, label: str) -> Mapping[str, Any]:
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except ValueError as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _resolve_input(path: Path, root: Path) -> Path:
    return path.resolve() if path.is_absolute() else _resolve_under_root(root, path.as_posix())


def _resolve_under_root(root: Path, relative: str) -> Path:
    safe = _safe_relative_path(relative)
    resolved = (root / Path(*PurePosixPath(safe).parts)).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"Benchmark path escapes repository root: {relative!r}")
    return resolved


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Benchmark provenance path must be repository-relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("Benchmark provenance path must not be an absolute drive path")
    return candidate.as_posix()


def _required_mapping(item: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = item.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"Benchmark manifest field {key!r} must be an object")
    return value


def _required_text(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Benchmark manifest field {key!r} must be non-empty text")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Benchmark optional text value must be non-empty when present")
    return value.strip()


def _positive_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Benchmark manifest field {key!r} must be a positive integer")
    return value
