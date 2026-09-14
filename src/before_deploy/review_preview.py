"""Deterministic review-scope preview independent from any advisory model."""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps
from pathlib import Path, PurePosixPath
from subprocess import DEVNULL, PIPE, TimeoutExpired, run
from typing import Iterable

from before_deploy.inventory import repository_path_exclusion_reason
from before_deploy.models import to_primitive


@dataclass(frozen=True)
class ReviewPreviewEntry:
    """One changed path and the deterministic decision to include or exclude it."""

    path: str
    status: str
    sources: tuple[str, ...]
    will_review: bool
    exclude_reason: str | None = None
    previous_path: str | None = None


@dataclass(frozen=True)
class ReviewPreview:
    """Provider-independent review selection for a repository state or Git range."""

    mode: str
    repository_path: str
    entries: tuple[ReviewPreviewEntry, ...]
    total_files: int
    reviewable_count: int
    excluded_count: int
    from_ref: str | None = None
    to_ref: str | None = None
    commit: str | None = None


def build_review_preview(
    repository: Path,
    *,
    max_file_bytes: int,
    from_ref: str | None = None,
    to_ref: str | None = None,
    commit: str | None = None,
) -> ReviewPreview:
    """Build a deterministic changed-file preview without invoking an LLM or scanner."""
    root = repository.resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {repository}")
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be greater than zero")
    if bool(from_ref) != bool(to_ref):
        raise ValueError("--from and --to must be supplied together")
    if commit and (from_ref or to_ref):
        raise ValueError("--commit cannot be combined with --from/--to")
    _ensure_git_worktree(root)

    if commit:
        mode = "COMMIT"
        changes = _commit_changes(root, commit)
    elif from_ref and to_ref:
        mode = "RANGE"
        changes = _range_changes(root, from_ref, to_ref)
    else:
        mode = "WORKSPACE"
        changes = _workspace_changes(root)

    entries = tuple(
        _preview_entry(root, change, max_file_bytes=max_file_bytes)
        for change in sorted(changes.values(), key=lambda item: item.path)
    )
    reviewable_count = sum(entry.will_review for entry in entries)
    return ReviewPreview(
        mode=mode,
        repository_path=root.as_posix(),
        entries=entries,
        total_files=len(entries),
        reviewable_count=reviewable_count,
        excluded_count=len(entries) - reviewable_count,
        from_ref=from_ref,
        to_ref=to_ref,
        commit=commit,
    )


def render_review_preview_json(preview: ReviewPreview) -> str:
    """Render stable machine-readable preview output."""
    return dumps(
        {"schema_version": 1, "review_preview": to_primitive(preview)},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_review_preview_markdown(preview: ReviewPreview) -> str:
    """Render a human-readable preview with explicit exclusion reasons."""
    lines = [
        "# Before Deploy Review Preview",
        "",
        f"- Mode: `{preview.mode}`",
        f"- Total changed files: **{preview.total_files}**",
        f"- Reviewable: **{preview.reviewable_count}**",
        f"- Excluded: **{preview.excluded_count}**",
    ]
    if preview.from_ref and preview.to_ref:
        lines.append(f"- Range: `{preview.from_ref}...{preview.to_ref}`")
    if preview.commit:
        lines.append(f"- Commit: `{preview.commit}`")
    lines.extend(["", "## Files", ""])
    if not preview.entries:
        lines.append("No changed files were detected.")
        return "\n".join(lines) + "\n"

    for entry in preview.entries:
        decision = "REVIEW" if entry.will_review else f"EXCLUDE:{entry.exclude_reason}"
        source_text = ",".join(entry.sources)
        rename_text = f" <- `{entry.previous_path}`" if entry.previous_path else ""
        lines.append(
            f"- `{decision}` `{entry.status}` `{entry.path}`{rename_text} "
            f"(source: `{source_text}`)"
        )
    return "\n".join(lines) + "\n"


@dataclass
class _Change:
    path: str
    status: str
    sources: set[str]
    previous_path: str | None = None


def _workspace_changes(root: Path) -> dict[str, _Change]:
    changes: dict[str, _Change] = {}
    _merge_changes(changes, _diff_changes(root, ["diff", "--name-status", "-z", "--find-renames"]), "WORKTREE")
    _merge_changes(
        changes,
        _diff_changes(root, ["diff", "--cached", "--name-status", "-z", "--find-renames"]),
        "STAGED",
    )
    untracked = _git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    for raw_path in _nul_tokens(untracked):
        path = _safe_git_path(raw_path)
        existing = changes.get(path)
        if existing is None:
            changes[path] = _Change(path=path, status="UNTRACKED", sources={"UNTRACKED"})
        else:
            existing.sources.add("UNTRACKED")
    return changes


def _range_changes(root: Path, from_ref: str, to_ref: str) -> dict[str, _Change]:
    return {
        item.path: item
        for item in _diff_changes(
            root,
            ["diff", "--name-status", "-z", "--find-renames", f"{from_ref}...{to_ref}"],
        )
    }


def _commit_changes(root: Path, commit: str) -> dict[str, _Change]:
    parent = _git_optional(root, ["rev-parse", "--verify", f"{commit}^"])
    if parent is None:
        args = [
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-status",
            "-r",
            "-z",
            "--find-renames",
            commit,
        ]
    else:
        args = ["diff", "--name-status", "-z", "--find-renames", f"{commit}^", commit]
    return {item.path: item for item in _diff_changes(root, args)}


def _diff_changes(root: Path, args: list[str]) -> list[_Change]:
    output = _git(root, args)
    tokens = _nul_tokens(output)
    changes: list[_Change] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if "\t" not in token:
            raise ValueError("Git returned an unexpected name-status record")
        raw_status, raw_path = token.split("\t", 1)
        status_code = raw_status[:1]
        path = _safe_git_path(raw_path)
        previous_path = None
        if status_code in {"R", "C"}:
            index += 1
            if index >= len(tokens):
                raise ValueError("Git returned an incomplete rename/copy record")
            previous_path = path
            path = _safe_git_path(tokens[index])
        changes.append(
            _Change(
                path=path,
                status=_status_name(status_code),
                sources=set(),
                previous_path=previous_path,
            )
        )
        index += 1
    return changes


def _merge_changes(target: dict[str, _Change], incoming: Iterable[_Change], source: str) -> None:
    for change in incoming:
        existing = target.get(change.path)
        if existing is None:
            change.sources.add(source)
            target[change.path] = change
            continue
        existing.sources.add(source)
        if _status_priority(change.status) > _status_priority(existing.status):
            existing.status = change.status
            existing.previous_path = change.previous_path


def _preview_entry(root: Path, change: _Change, *, max_file_bytes: int) -> ReviewPreviewEntry:
    if change.status == "DELETED":
        reason = "deleted"
    else:
        reason = repository_path_exclusion_reason(
            root,
            Path(change.path),
            max_file_bytes=max_file_bytes,
        )
    return ReviewPreviewEntry(
        path=change.path,
        status=change.status,
        sources=tuple(sorted(change.sources)) or ("GIT",),
        will_review=reason is None,
        exclude_reason=reason,
        previous_path=change.previous_path,
    )


def _ensure_git_worktree(root: Path) -> None:
    result = _git(root, ["rev-parse", "--is-inside-work-tree"]).strip()
    if result != "true":
        raise ValueError("Review preview requires a Git worktree")


def _git(root: Path, args: list[str]) -> str:
    try:
        completed = run(
            ["git", "-C", str(root), *args],
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError as error:
        raise ValueError("Review preview requires Git on PATH") from error
    except TimeoutExpired as error:
        raise ValueError("Git command timed out while building review preview") from error
    if completed.returncode != 0:
        raise ValueError("Git could not resolve the requested review scope")
    return completed.stdout


def _git_optional(root: Path, args: list[str]) -> str | None:
    try:
        completed = run(
            ["git", "-C", str(root), *args],
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _nul_tokens(value: str) -> list[str]:
    return [token for token in value.split("\0") if token]


def _safe_git_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Git returned an unsafe repository-relative path")
    return candidate.as_posix()


def _status_name(code: str) -> str:
    return {
        "A": "ADDED",
        "C": "COPIED",
        "D": "DELETED",
        "M": "MODIFIED",
        "R": "RENAMED",
        "T": "TYPE_CHANGED",
        "U": "UNMERGED",
    }.get(code, "CHANGED")


def _status_priority(status: str) -> int:
    return {
        "DELETED": 7,
        "UNMERGED": 6,
        "RENAMED": 5,
        "COPIED": 4,
        "ADDED": 3,
        "TYPE_CHANGED": 2,
        "MODIFIED": 1,
    }.get(status, 0)
