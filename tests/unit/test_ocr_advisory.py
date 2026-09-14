from pathlib import Path
from types import SimpleNamespace

from before_deploy.ocr_advisory import OcrAdvisoryOptions, run_ocr_advisory


def test_ocr_advisory_runs_fixed_command_and_normalizes_output(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    observed = {}

    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        observed["command"] = command
        output_path = Path(command[command.index("--output") + 1])
        output_path.write_text(
            '[{"path":"src/app.py","content":"Possible bug","start_line":7,'
            '"severity":"high","category":"bug"}]',
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(
        repository,
        OcrAdvisoryOptions(from_ref="main", to_ref="HEAD", timeout_seconds=30),
    )

    assert imported.status == "COMPLETED"
    assert imported.source == "open-code-review"
    assert imported.input_name == "ocr"
    assert len(imported.findings) == 1
    assert imported.findings[0].gate_effect == "NONE"
    assert observed["command"][:2] == ["/usr/bin/ocr", "review"]
    assert observed["command"][observed["command"].index("--repo") + 1] == str(
        repository.resolve()
    )
    assert "--audience" in observed["command"]
    assert "agent" in observed["command"]
    assert "--format" in observed["command"]
    assert "json" in observed["command"]
    assert observed["command"][-4:] == ["--from", "main", "--to", "HEAD"]


def test_ocr_failure_is_gate_neutral_advisory_error(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")
    monkeypatch.setattr(
        "before_deploy.ocr_advisory.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=17),
    )

    imported = run_ocr_advisory(repository, OcrAdvisoryOptions())

    assert imported.status == "ERROR"
    assert imported.findings == ()
    assert imported.message == "OpenCodeReview exited with code 17"


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


def test_ocr_output_size_limit_is_enforced(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    monkeypatch.setattr("before_deploy.ocr_advisory.which", lambda name: "/usr/bin/ocr")

    def fake_run(command, **kwargs):
        output_path = Path(command[command.index("--output") + 1])
        output_path.write_text("[" + (" " * 200) + "]", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("before_deploy.ocr_advisory.run", fake_run)

    imported = run_ocr_advisory(
        repository,
        OcrAdvisoryOptions(max_output_bytes=100),
    )

    assert imported.status == "ERROR"
    assert "size limit" in (imported.message or "")
