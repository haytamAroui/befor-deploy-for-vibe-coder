from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from before_deploy.cli import build_parser, main
from before_deploy.review_preview import build_review_preview, render_review_preview_json


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.email", "preview@example.invalid")
    _git(repository, "config", "user.name", "Preview Test")
    (repository / "src").mkdir()
    (repository / "src" / "app.py").write_text("print('v1')\n", encoding="utf-8")
    (repository / "old.py").write_text("print('old')\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "initial")
    return repository


def _entry_map(preview):
    return {entry.path: entry for entry in preview.entries}


def test_workspace_preview_exposes_reviewable_and_excluded_changes(tmp_path):
    repository = _repo(tmp_path)
    (repository / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
    (repository / "old.py").unlink()
    (repository / "new.py").write_text("print('new')\n", encoding="utf-8")
    (repository / "node_modules").mkdir()
    (repository / "node_modules" / "pkg.js").write_text("export default 1\n", encoding="utf-8")
    (repository / "large.txt").write_text("x" * 200, encoding="utf-8")

    preview = build_review_preview(repository, max_file_bytes=100)
    entries = _entry_map(preview)

    assert preview.mode == "WORKSPACE"
    assert entries["src/app.py"].will_review is True
    assert entries["new.py"].will_review is True
    assert entries["old.py"].will_review is False
    assert entries["old.py"].exclude_reason == "deleted"
    assert entries["node_modules/pkg.js"].exclude_reason == "excluded_directory"
    assert entries["large.txt"].exclude_reason == "too_large"
    assert preview.reviewable_count == 2
    assert preview.excluded_count == 3


def test_workspace_preview_tracks_staged_rename(tmp_path):
    repository = _repo(tmp_path)
    _git(repository, "mv", "old.py", "moved.py")

    preview = build_review_preview(repository, max_file_bytes=1_000_000)
    entry = _entry_map(preview)["moved.py"]

    assert entry.status == "RENAMED"
    assert entry.previous_path == "old.py"
    assert entry.sources == ("STAGED",)
    assert entry.will_review is True


def test_range_and_commit_preview_use_explicit_git_scope(tmp_path):
    repository = _repo(tmp_path)
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
    (repository / "added.py").write_text("print('added')\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "change")
    head = _git(repository, "rev-parse", "HEAD")

    range_preview = build_review_preview(
        repository,
        max_file_bytes=1_000_000,
        from_ref=base,
        to_ref=head,
    )
    commit_preview = build_review_preview(
        repository,
        max_file_bytes=1_000_000,
        commit=head,
    )

    assert range_preview.mode == "RANGE"
    assert set(_entry_map(range_preview)) == {"added.py", "src/app.py"}
    assert commit_preview.mode == "COMMIT"
    assert set(_entry_map(commit_preview)) == {"added.py", "src/app.py"}


def test_preview_rejects_ambiguous_scope(tmp_path):
    repository = _repo(tmp_path)

    with pytest.raises(ValueError, match="supplied together"):
        build_review_preview(repository, max_file_bytes=1_000_000, from_ref="HEAD~1")

    with pytest.raises(ValueError, match="cannot be combined"):
        build_review_preview(
            repository,
            max_file_bytes=1_000_000,
            from_ref="HEAD~1",
            to_ref="HEAD",
            commit="HEAD",
        )


def test_preview_cli_writes_only_preview_artifacts(tmp_path):
    repository = _repo(tmp_path)
    (repository / "new.py").write_text("print('new')\n", encoding="utf-8")
    output_dir = tmp_path / "preview-output"

    exit_code = main(
        [
            "review",
            str(repository),
            "--preview",
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "preview.json").is_file()
    assert (output_dir / "preview.md").is_file()
    assert not (output_dir / "report.json").exists()
    assert not (output_dir / "review.json").exists()
    rendered = (output_dir / "preview.json").read_text(encoding="utf-8")
    assert '"mode": "WORKSPACE"' in rendered
    assert '"path": "new.py"' in rendered


def test_review_scope_flags_keep_ocr_aliases_for_compatibility():
    parser = build_parser()
    generic = parser.parse_args(
        ["review", ".", "--ocr", "--from", "main", "--to", "HEAD"]
    )
    legacy = parser.parse_args(
        ["review", ".", "--ocr", "--ocr-from", "main", "--ocr-to", "HEAD"]
    )

    assert generic.review_from == legacy.review_from == "main"
    assert generic.review_to == legacy.review_to == "HEAD"


def test_preview_json_has_explicit_selection_counts(tmp_path):
    repository = _repo(tmp_path)
    (repository / "new.py").write_text("print('new')\n", encoding="utf-8")

    preview = build_review_preview(repository, max_file_bytes=1_000_000)
    rendered = render_review_preview_json(preview)

    assert '"schema_version": 1' in rendered
    assert '"reviewable_count": 1' in rendered
    assert '"excluded_count": 0' in rendered
