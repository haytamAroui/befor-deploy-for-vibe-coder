"""Deterministic, bounded context selection for advisory providers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from json import dumps
from pathlib import Path, PurePosixPath
from subprocess import DEVNULL, PIPE, TimeoutExpired, run

from before_deploy.inventory import (
    EXCLUDED_DIRECTORY_NAMES,
    EXCLUDED_FILE_NAMES,
    resolve_git_revision,
)
from before_deploy.models import to_primitive
from before_deploy.review_preview import ReviewPreview, ReviewPreviewEntry, build_review_preview

ADVISORY_CONTEXT_SCHEMA_VERSION = 1
ADVISORY_CONTEXT_AUTHORITY = "ADVISORY_CONTEXT"
ADVISORY_CONTEXT_GATE_EFFECT = "NONE"
DEFAULT_MAX_CONTEXT_BYTES = 4_000_000


@dataclass(frozen=True)
class AdvisoryContextEntry:
    """Metadata binding one selected source file to the exact bytes sent to a provider."""

    path: str
    status: str
    sources: tuple[str, ...]
    size_bytes: int
    content_sha256: str
    start_line: int | None
    end_line: int | None
    previous_path: str | None = None
    selection_reason: str = "CHANGED_FILE"


@dataclass(frozen=True)
class AdvisoryContextExclusion:
    """One changed path excluded from provider context for a deterministic reason."""

    path: str
    status: str
    sources: tuple[str, ...]
    reason: str
    previous_path: str | None = None


@dataclass(frozen=True)
class AdvisoryContextManifest:
    """Content-free, reproducible description of one materialized advisory context."""

    mode: str
    source_revision: str | None
    max_file_bytes: int
    max_context_bytes: int
    selected: tuple[AdvisoryContextEntry, ...]
    excluded: tuple[AdvisoryContextExclusion, ...]
    total_changed_files: int
    selected_file_count: int
    excluded_file_count: int
    total_selected_bytes: int
    context_sha256: str
    from_ref: str | None = None
    to_ref: str | None = None
    commit: str | None = None
    authority: str = ADVISORY_CONTEXT_AUTHORITY
    gate_effect: str = ADVISORY_CONTEXT_GATE_EFFECT


@dataclass(frozen=True)
class AdvisoryContextFile:
    """Exact UTF-8 source content selected for advisory execution."""

    path: str
    content: str


@dataclass(frozen=True)
class AdvisoryContext:
    """Internal provider context plus a redaction-safe manifest for inspection."""

    repository: Path
    manifest: AdvisoryContextManifest
    files: tuple[AdvisoryContextFile, ...]


def build_advisory_context(
    repository: Path,
    *,
    max_file_bytes: int,
    max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES,
    from_ref: str | None = None,
    to_ref: str | None = None,
    commit: str | None = None,
) -> AdvisoryContext:
    """Select exact provider bytes deterministically without invoking an advisory provider."""
    if max_context_bytes <= 0:
        raise ValueError("max_context_bytes must be greater than zero")

    root = repository.resolve()
    preview = build_review_preview(
        root,
        max_file_bytes=max_file_bytes,
        from_ref=from_ref,
        to_ref=to_ref,
        commit=commit,
    )
    source_revision = _resolve_scope_revision(root, preview)

    selected: list[AdvisoryContextEntry] = []
    excluded: list[AdvisoryContextExclusion] = []
    files: list[AdvisoryContextFile] = []
    total_selected_bytes = 0

    for entry in preview.entries:
        path_reason = _path_only_exclusion_reason(entry.path)
        if path_reason is not None:
            excluded.append(_excluded(entry, path_reason))
            continue

        content, reason = _materialize_source(root, preview, entry, source_revision)
        if reason is not None:
            excluded.append(_excluded(entry, reason))
            continue
        assert content is not None

        if len(content) > max_file_bytes:
            excluded.append(_excluded(entry, "too_large"))
            continue
        if b"\x00" in content:
            excluded.append(_excluded(entry, "binary"))
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            excluded.append(_excluded(entry, "non_utf8"))
            continue
        if total_selected_bytes + len(content) > max_context_bytes:
            excluded.append(_excluded(entry, "context_budget"))
            continue

        line_count = len(text.splitlines())
        selected_entry = AdvisoryContextEntry(
            path=entry.path,
            status=entry.status,
            sources=entry.sources,
            size_bytes=len(content),
            content_sha256=sha256(content).hexdigest(),
            start_line=1 if line_count else None,
            end_line=line_count if line_count else None,
            previous_path=entry.previous_path,
        )
        selected.append(selected_entry)
        files.append(AdvisoryContextFile(path=entry.path, content=text))
        total_selected_bytes += len(content)

    manifest = AdvisoryContextManifest(
        mode=preview.mode,
        source_revision=source_revision,
        max_file_bytes=max_file_bytes,
        max_context_bytes=max_context_bytes,
        selected=tuple(selected),
        excluded=tuple(excluded),
        total_changed_files=preview.total_files,
        selected_file_count=len(selected),
        excluded_file_count=len(excluded),
        total_selected_bytes=total_selected_bytes,
        context_sha256="",
        from_ref=from_ref,
        to_ref=to_ref,
        commit=commit,
    )
    manifest = replace(manifest, context_sha256=_manifest_digest(manifest))
    context = AdvisoryContext(repository=root, manifest=manifest, files=tuple(files))
    validate_advisory_context(context)
    return context


def validate_advisory_context(context: AdvisoryContext) -> None:
    """Validate context integrity before any provider receives it."""
    manifest = context.manifest
    if manifest.authority != ADVISORY_CONTEXT_AUTHORITY:
        raise ValueError("Advisory context authority must remain ADVISORY_CONTEXT")
    if manifest.gate_effect != ADVISORY_CONTEXT_GATE_EFFECT:
        raise ValueError("Advisory context gate_effect must remain NONE")
    if manifest.max_file_bytes <= 0 or manifest.max_context_bytes <= 0:
        raise ValueError("Advisory context byte limits must be positive")
    if manifest.context_sha256 != _manifest_digest(replace(manifest, context_sha256="")):
        raise ValueError("Advisory context manifest digest mismatch")

    selected_paths = [entry.path for entry in manifest.selected]
    excluded_paths = [entry.path for entry in manifest.excluded]
    if selected_paths != sorted(selected_paths) or len(selected_paths) != len(set(selected_paths)):
        raise ValueError("Advisory context selected paths must be unique and sorted")
    if excluded_paths != sorted(excluded_paths) or len(excluded_paths) != len(set(excluded_paths)):
        raise ValueError("Advisory context excluded paths must be unique and sorted")
    if set(selected_paths) & set(excluded_paths):
        raise ValueError("Advisory context path cannot be both selected and excluded")
    if manifest.total_changed_files != len(selected_paths) + len(excluded_paths):
        raise ValueError("Advisory context changed-file count is inconsistent")
    if manifest.selected_file_count != len(selected_paths):
        raise ValueError("Advisory context selected-file count is inconsistent")
    if manifest.excluded_file_count != len(excluded_paths):
        raise ValueError("Advisory context excluded-file count is inconsistent")
    if tuple(file.path for file in context.files) != tuple(selected_paths):
        raise ValueError("Advisory context materialized files do not match the manifest")

    total_bytes = 0
    for entry, materialized in zip(manifest.selected, context.files, strict=True):
        _safe_relative_path(entry.path)
        content = materialized.content.encode("utf-8")
        if len(content) != entry.size_bytes:
            raise ValueError(f"Advisory context size mismatch for {entry.path}")
        if sha256(content).hexdigest() != entry.content_sha256:
            raise ValueError(f"Advisory context content hash mismatch for {entry.path}")
        line_count = len(materialized.content.splitlines())
        expected_start = 1 if line_count else None
        expected_end = line_count if line_count else None
        if (entry.start_line, entry.end_line) != (expected_start, expected_end):
            raise ValueError(f"Advisory context line range mismatch for {entry.path}")
        total_bytes += len(content)
    if total_bytes != manifest.total_selected_bytes:
        raise ValueError("Advisory context selected-byte count is inconsistent")
    if total_bytes > manifest.max_context_bytes:
        raise ValueError("Advisory context exceeds its declared byte budget")


def render_advisory_context_json(context: AdvisoryContext) -> str:
    """Render the content-free context manifest; raw source content is never serialized."""
    validate_advisory_context(context)
    return dumps(
        {
            "schema_version": ADVISORY_CONTEXT_SCHEMA_VERSION,
            "advisory_context": to_primitive(context.manifest),
        },
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_advisory_context_markdown(context: AdvisoryContext) -> str:
    """Render inspectable context provenance without copying source content."""
    validate_advisory_context(context)
    manifest = context.manifest
    lines = [
        "# Before Deploy Advisory Context",
        "",
        f"- Mode: `{manifest.mode}`",
        f"- Context SHA-256: `{manifest.context_sha256}`",
        f"- Source revision: `{manifest.source_revision or 'WORKSPACE_WITHOUT_HEAD'}`",
        f"- Selected files: **{manifest.selected_file_count}**",
        f"- Excluded files: **{manifest.excluded_file_count}**",
        f"- Selected bytes: **{manifest.total_selected_bytes}** / **{manifest.max_context_bytes}**",
        f"- Authority: `{manifest.authority}`",
        f"- Gate effect: `{manifest.gate_effect}`",
        "",
        "## Selected",
        "",
    ]
    if not manifest.selected:
        lines.append("No source files were selected.")
    for entry in manifest.selected:
        lines.append(
            f"- `{entry.path}` bytes={entry.size_bytes} sha256=`{entry.content_sha256}` "
            f"range={entry.start_line or '-'}..{entry.end_line or '-'}"
        )
    lines.extend(["", "## Excluded", ""])
    if not manifest.excluded:
        lines.append("No changed files were excluded.")
    for entry in manifest.excluded:
        lines.append(f"- `{entry.path}` reason=`{entry.reason}`")
    return "\n".join(lines) + "\n"


def context_summary(context: AdvisoryContext) -> str:
    """Return a bounded provenance summary suitable for unified advisory source metadata."""
    manifest = context.manifest
    return (
        f"context_sha256={manifest.context_sha256} "
        f"selected_files={manifest.selected_file_count} "
        f"selected_bytes={manifest.total_selected_bytes}/{manifest.max_context_bytes} "
        f"excluded_files={manifest.excluded_file_count}"
    )


def _manifest_digest(manifest: AdvisoryContextManifest) -> str:
    payload = {
        "schema_version": ADVISORY_CONTEXT_SCHEMA_VERSION,
        "advisory_context": to_primitive(replace(manifest, context_sha256="")),
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _resolve_scope_revision(root: Path, preview: ReviewPreview) -> str | None:
    if preview.mode == "RANGE":
        assert preview.to_ref is not None
        return _resolve_commit(root, preview.to_ref)
    if preview.mode == "COMMIT":
        assert preview.commit is not None
        return _resolve_commit(root, preview.commit)
    return resolve_git_revision(root)


def _resolve_commit(root: Path, ref: str) -> str:
    value = _git_text(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    revision = value.strip()
    if not revision:
        raise ValueError("Git resolved an empty advisory context revision")
    return revision


def _materialize_source(
    root: Path,
    preview: ReviewPreview,
    entry: ReviewPreviewEntry,
    source_revision: str | None,
) -> tuple[bytes | None, str | None]:
    if entry.status == "DELETED":
        return None, "deleted"
    if preview.mode == "WORKSPACE":
        safe = _safe_relative_path(entry.path)
        relative = Path(*PurePosixPath(safe).parts)
        path = root / relative
        current = root
        try:
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    return None, "symlink"
            if not path.is_file():
                return None, "not_regular_file"
            resolved = path.resolve(strict=False)
            if resolved != root and root not in resolved.parents:
                return None, "path_escape"
            return path.read_bytes(), None
        except OSError:
            return None, "unreadable"

    if source_revision is None:
        return None, "unresolved_revision"
    tree_entry = _git_bytes(
        root,
        ["ls-tree", "-z", "--full-tree", source_revision, "--", entry.path],
    )
    records = [record for record in tree_entry.split(b"\0") if record]
    if len(records) != 1:
        return None, "missing_at_source_revision"
    metadata, separator, _ = records[0].partition(b"\t")
    fields = metadata.split()
    if not separator or len(fields) != 3:
        return None, "invalid_git_tree_entry"
    mode, object_type, object_id = fields
    if object_type != b"blob" or mode not in {b"100644", b"100755"}:
        return None, "not_regular_file"
    return _git_bytes(root, ["cat-file", "blob", object_id.decode("ascii")]), None


def _path_only_exclusion_reason(path: str) -> str | None:
    safe = _safe_relative_path(path)
    relative = PurePosixPath(safe)
    if relative.name in EXCLUDED_FILE_NAMES:
        return "excluded_file_name"
    if any(part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts[:-1]):
        return "excluded_directory"
    return None


def _excluded(entry: ReviewPreviewEntry, reason: str) -> AdvisoryContextExclusion:
    return AdvisoryContextExclusion(
        path=entry.path,
        status=entry.status,
        sources=entry.sources,
        reason=reason,
        previous_path=entry.previous_path,
    )


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Advisory context path must be repository-relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("Advisory context path must not be an absolute drive path")
    return candidate.as_posix()


def _git_text(root: Path, args: list[str]) -> str:
    return _git_bytes(root, args).decode("utf-8")


def _git_bytes(root: Path, args: list[str]) -> bytes:
    try:
        completed = run(
            ["git", "-C", str(root), *args],
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=DEVNULL,
            timeout=10,
            check=False,
        )
    except FileNotFoundError as error:
        raise ValueError("Advisory context selection requires Git on PATH") from error
    except TimeoutExpired as error:
        raise ValueError("Git command timed out while selecting advisory context") from error
    if completed.returncode != 0:
        raise ValueError("Git could not resolve advisory context source bytes")
    return completed.stdout
