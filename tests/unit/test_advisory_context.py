from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from subprocess import run

import pytest

from before_deploy.advisory_context import (
    ADVISORY_CONTEXT_AUTHORITY,
    ADVISORY_CONTEXT_GATE_EFFECT,
    build_advisory_context,
    render_advisory_context_json,
    validate_advisory_context,
)


# Fixtures are written with newline="\n" so the bytes on disk are exactly what the
# assertions hash. Path.write_text defaults to newline=None, which translates "\n" to
# os.linesep and would make every size and digest assertion platform-dependent.
def _git(repository: Path, *arguments: str) -> str:
    completed = run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Before Deploy Tests")
    _git(repository, "config", "user.email", "tests@before-deploy.invalid")
    (repository / "src").mkdir()
    (repository / "src" / "a.py").write_text("a = 1\n", encoding="utf-8", newline="\n")
    (repository / "src" / "b.py").write_text("b = 1\n", encoding="utf-8", newline="\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "initial")
    return repository


def test_workspace_context_is_sorted_hashed_and_reproducible(tmp_path: Path):
    repository = _repository(tmp_path)
    (repository / "src" / "b.py").write_text("b = 2\n", encoding="utf-8", newline="\n")
    (repository / "src" / "a.py").write_text("a = 2\n", encoding="utf-8", newline="\n")

    first = build_advisory_context(
        repository,
        max_file_bytes=1000,
        max_context_bytes=1000,
    )
    second = build_advisory_context(
        repository,
        max_file_bytes=1000,
        max_context_bytes=1000,
    )

    assert [entry.path for entry in first.manifest.selected] == ["src/a.py", "src/b.py"]
    assert [item.path for item in first.files] == ["src/a.py", "src/b.py"]
    assert first.manifest.context_sha256 == second.manifest.context_sha256
    assert first.manifest.total_selected_bytes == len(b"a = 2\n") + len(b"b = 2\n")
    assert first.manifest.selected[0].content_sha256 == sha256(b"a = 2\n").hexdigest()
    assert first.manifest.authority == ADVISORY_CONTEXT_AUTHORITY
    assert first.manifest.gate_effect == ADVISORY_CONTEXT_GATE_EFFECT


def test_context_budget_selects_whole_files_in_stable_path_order(tmp_path: Path):
    repository = _repository(tmp_path)
    (repository / "src" / "a.py").write_text("aaaa\n", encoding="utf-8", newline="\n")
    (repository / "src" / "b.py").write_text("bbbb\n", encoding="utf-8", newline="\n")

    context = build_advisory_context(
        repository,
        max_file_bytes=1000,
        max_context_bytes=5,
    )

    assert [entry.path for entry in context.manifest.selected] == ["src/a.py"]
    assert [(entry.path, entry.reason) for entry in context.manifest.excluded] == [
        ("src/b.py", "context_budget")
    ]
    assert context.manifest.total_selected_bytes == 5


def test_range_context_reads_target_git_tree_not_current_worktree(tmp_path: Path):
    repository = _repository(tmp_path)
    target = "target tree bytes\n"
    (repository / "src" / "a.py").write_text(target, encoding="utf-8", newline="\n")
    _git(repository, "add", "src/a.py")
    _git(repository, "commit", "-m", "target")
    target_revision = _git(repository, "rev-parse", "HEAD")

    (repository / "src" / "a.py").write_text("different workspace bytes\n", encoding="utf-8", newline="\n")

    context = build_advisory_context(
        repository,
        max_file_bytes=1000,
        max_context_bytes=1000,
        from_ref="HEAD^",
        to_ref="HEAD",
    )

    assert context.manifest.mode == "RANGE"
    assert context.manifest.source_revision == target_revision
    assert context.files[0].content == target
    assert context.manifest.selected[0].content_sha256 == sha256(target.encode()).hexdigest()


def test_context_digest_changes_when_workspace_bytes_change(tmp_path: Path):
    repository = _repository(tmp_path)
    path = repository / "src" / "a.py"
    path.write_text("a = 2\n", encoding="utf-8", newline="\n")
    first = build_advisory_context(repository, max_file_bytes=1000, max_context_bytes=1000)

    path.write_text("a = 3\n", encoding="utf-8", newline="\n")
    second = build_advisory_context(repository, max_file_bytes=1000, max_context_bytes=1000)

    assert first.manifest.context_sha256 != second.manifest.context_sha256
    assert first.manifest.selected[0].content_sha256 != second.manifest.selected[0].content_sha256


def test_rendered_manifest_is_content_free_but_inspectable(tmp_path: Path):
    repository = _repository(tmp_path)
    secret_like_source = "token = 'do-not-copy-raw-source'\n"
    (repository / "src" / "a.py").write_text(secret_like_source, encoding="utf-8", newline="\n")

    context = build_advisory_context(repository, max_file_bytes=1000, max_context_bytes=1000)
    rendered = render_advisory_context_json(context)

    assert "do-not-copy-raw-source" not in rendered
    assert context.manifest.context_sha256 in rendered
    assert sha256(secret_like_source.encode()).hexdigest() in rendered
    assert '"gate_effect": "NONE"' in rendered


def test_context_integrity_validation_rejects_materialized_content_drift(tmp_path: Path):
    repository = _repository(tmp_path)
    (repository / "src" / "a.py").write_text("a = 2\n", encoding="utf-8", newline="\n")
    context = build_advisory_context(repository, max_file_bytes=1000, max_context_bytes=1000)
    tampered_file = replace(context.files[0], content="a = 999\n")
    tampered = replace(context, files=(tampered_file, *context.files[1:]))

    with pytest.raises(ValueError, match="size mismatch|content hash mismatch"):
        validate_advisory_context(tampered)


def test_non_utf8_changed_file_is_excluded_with_explicit_reason(tmp_path: Path):
    repository = _repository(tmp_path)
    path = repository / "src" / "a.py"
    path.write_bytes(b"\xff\xfe\xfd")

    context = build_advisory_context(repository, max_file_bytes=1000, max_context_bytes=1000)

    assert context.manifest.selected == ()
    assert [(entry.path, entry.reason) for entry in context.manifest.excluded] == [
        ("src/a.py", "non_utf8")
    ]


def test_workspace_symlink_is_excluded_without_reading_target(
    tmp_path: Path, symlink_supported: None
):
    repository = _repository(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("outside_secret = True\n", encoding="utf-8", newline="\n")
    path = repository / "src" / "a.py"
    path.unlink()
    path.symlink_to(outside)

    context = build_advisory_context(repository, max_file_bytes=1000, max_context_bytes=1000)

    assert context.manifest.selected == ()
    assert [(entry.path, entry.reason) for entry in context.manifest.excluded] == [
        ("src/a.py", "symlink")
    ]
    assert context.files == ()
