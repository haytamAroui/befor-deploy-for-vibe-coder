from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from before_deploy.ocr_advisory import OcrAdvisoryOptions, run_ocr_advisory


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path, *, two_files: bool = False) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.email", "ocr-test@example.invalid")
    _git(repository, "config", "user.name", "OCR Test")
    (repository / "src").mkdir()
    (repository / "src" / "app.py").write_text("print('v1')\n", encoding="utf-8")
    if two_files:
        (repository / "src" / "other.py").write_text("print('v1')\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "initial")
    (repository / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
    if two_files:
        (repository / "src" / "other.py").write_text("print('v2')\n", encoding="utf-8")
    return repository


def _write_preview(command: list[str], paths: list[str]) -> None:
    output_path = Path(command[command.index("--output") + 1])
    output_path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": path,
                        "status": "modified",
                        "will_review": True,
                    }
                    for path in paths
                ],
                "total_files": len(paths),
                "reviewable_count": len(paths),
                "excluded_count": 0,
            }
        ),
        encoding="utf-8",
    )


def _write_review(
    command: list[str],
    *,
    selected_paths: list[str],
    malformed_manifest: bool = False,
) -> None:
    output_path = Path(command[command.index("--output") + 1])
    manifest = {
        "schema_version": "ocr.run-manifest/v1",
        "coverage": {
            "selected": [{"path": path} for path in selected_paths],
        },
    }
    if malformed_manifest:
        manifest["coverage"] = {"selected": "not-an-array"}
    output_path.write_text(
        json.dumps(
            {
                "status": "complete",
                "comments": [
                    {
                        "path": "src/app.py",
                        "content": "Possible bug",
                        "start_line": 1,
                        "end_line": 1,
                        "severity": "high",
                        "category": "bug",
                        "thinking": "must not be imported",
                        "existing_code": "secret raw code",
                        "suggestion_code": "replacement raw code",
                    }
                ],
                "manifest": manifest,
            }
        ),
        encoding="utf-8",
    )


def test_ocr_scope_match_runs_review_and_normalizes_findings(tmp_path, monkeypatch):
    repository = _repository(tmp_path)
    commands: list[list[str]] = []
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        commands.append(command)
        if "--preview" in command:
            _write_preview(command, ["src/app.py"])
        else:
            _write_review(command, selected_paths=["src/app.py"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions(timeout_seconds=30))

    assert imported.status == "COMPLETED"
    assert imported.scope_status == "MATCHED"
    assert "same 1 reviewable path" in (imported.scope_message or "")
    assert len(imported.findings) == 1
    assert imported.findings[0].gate_effect == "NONE"
    assert imported.findings[0].source == "open-code-review"
    assert len(commands) == 2
    assert "--preview" in commands[0]
    assert "--preview" not in commands[1]
    assert commands[0][:2] == ["/usr/bin/ocr", "review"]
    assert commands[0][commands[0].index("--repo") + 1] == str(repository.resolve())


def test_ocr_preflight_expansion_stops_before_llm_review(tmp_path, monkeypatch):
    repository = _repository(tmp_path)
    calls = 0
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        nonlocal calls
        calls += 1
        _write_preview(command, ["src/app.py", "src/not-changed.py"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert calls == 1
    assert imported.status == "ERROR"
    assert imported.scope_status == "EXPANDED"
    assert imported.findings == ()
    assert "LLM review was not started" in (imported.scope_message or "")


def test_ocr_final_manifest_drift_discards_findings(tmp_path, monkeypatch):
    repository = _repository(tmp_path, two_files=True)
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        if "--preview" in command:
            _write_preview(command, ["src/app.py"])
        else:
            _write_review(command, selected_paths=["src/other.py"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert imported.status == "ERROR"
    assert imported.scope_status == "DRIFT"
    assert imported.findings == ()
    assert "did not match its preflight" in (imported.scope_message or "")


def test_ocr_partial_scope_is_visible_but_remains_advisory(tmp_path, monkeypatch):
    repository = _repository(tmp_path, two_files=True)
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        if "--preview" in command:
            _write_preview(command, ["src/app.py"])
        else:
            _write_review(command, selected_paths=["src/app.py"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert imported.status == "COMPLETED"
    assert imported.scope_status == "PARTIAL"
    assert len(imported.findings) == 1
    assert imported.findings[0].gate_effect == "NONE"
    assert "1 allowed path" in (imported.scope_message or "")


def test_malformed_supported_ocr_manifest_is_gate_neutral_source_error(tmp_path, monkeypatch):
    repository = _repository(tmp_path)
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        if "--preview" in command:
            _write_preview(command, ["src/app.py"])
        else:
            _write_review(
                command,
                selected_paths=["src/app.py"],
                malformed_manifest=True,
            )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert imported.status == "ERROR"
    assert imported.scope_status == "INVALID_MANIFEST"
    assert imported.findings == ()
    assert "malformed" in (imported.scope_message or "")


def test_ocr_legacy_output_without_manifest_is_preflight_only(tmp_path, monkeypatch):
    repository = _repository(tmp_path)
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        output_path = Path(command[command.index("--output") + 1])
        if "--preview" in command:
            _write_preview(command, ["src/app.py"])
        else:
            output_path.write_text(
                json.dumps(
                    {
                        "comments": [
                            {
                                "path": "src/app.py",
                                "content": "Possible bug",
                                "start_line": 1,
                                "severity": "high",
                                "category": "bug",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert imported.status == "COMPLETED"
    assert imported.scope_status == "PREFLIGHT_ONLY"
    assert len(imported.findings) == 1


def test_ocr_preview_failure_is_gate_neutral_advisory_error(tmp_path, monkeypatch):
    repository = _repository(tmp_path)
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")
    monkeypatch.setattr(
        "before_deploy.ocr_advisory.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=17),
    )

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert imported.status == "ERROR"
    assert imported.findings == ()
    assert imported.message == "OpenCodeReview preview exited with code 17"
    assert imported.scope_status == "NOT_CHECKED"


def test_ocr_rejects_invalid_diff_mode_without_execution(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(
        repository,
        OcrAdvisoryOptions(from_ref="main", to_ref="HEAD", commit="abc123"),
    )

    assert imported.status == "ERROR"
    assert "cannot be combined" in (imported.message or "")
    assert called is False


def test_ocr_scope_respects_configured_file_size_limit(tmp_path, monkeypatch):
    repository = _repository(tmp_path)
    (repository / "large.py").write_text("x" * 200, encoding="utf-8")
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        _write_preview(command, ["large.py"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(
        repository,
        OcrAdvisoryOptions(max_file_bytes=100),
    )

    assert imported.status == "ERROR"
    assert imported.scope_status == "EXPANDED"
