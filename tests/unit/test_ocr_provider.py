from __future__ import annotations

from pathlib import Path
from subprocess import run

from before_deploy.advisory import AdvisoryImport
from before_deploy.advisory_provider import AdvisoryProviderRequest, execute_advisory_provider
from before_deploy.ocr_advisory import OCR_SOURCE, OCR_SOURCE_FORMAT
from before_deploy.ocr_provider import OcrAdvisoryProvider


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
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "app.py")
    _git(repository, "commit", "-m", "initial")
    (repository / "app.py").write_text("value = 2\n", encoding="utf-8")
    _git(repository, "add", "app.py")
    _git(repository, "commit", "-m", "target")
    return repository


def test_ocr_provider_maps_generic_request_to_existing_adapter(tmp_path: Path, monkeypatch):
    repository = _repository(tmp_path)
    captured = {}

    def fake_run(repository_path, options):
        captured["repository"] = repository_path
        captured["options"] = options
        return AdvisoryImport(
            input_name="ocr-native",
            source=OCR_SOURCE,
            source_format=OCR_SOURCE_FORMAT,
            findings=(),
            status="COMPLETED",
            scope_status="MATCHED",
        )

    monkeypatch.setattr("before_deploy.ocr_provider.run_ocr_advisory", fake_run)
    provider = OcrAdvisoryProvider(timeout_seconds=45, max_output_bytes=123_456)
    request = AdvisoryProviderRequest(
        repository=repository,
        max_file_bytes=654_321,
        from_ref="HEAD^",
        to_ref="HEAD",
    )

    result = execute_advisory_provider(provider, request)

    options = captured["options"]
    assert captured["repository"] == repository.resolve()
    assert options.timeout_seconds == 45
    assert options.max_output_bytes == 123_456
    assert options.max_file_bytes == 654_321
    assert options.from_ref == "HEAD^"
    assert options.to_ref == "HEAD"
    assert options.commit is None
    assert result.input_name == "ocr"
    assert result.source == OCR_SOURCE
    assert result.source_format == OCR_SOURCE_FORMAT
    assert result.scope_status == "MATCHED"
    assert "context_sha256=" in (result.scope_message or "")


def test_ocr_provider_refuses_to_run_when_context_budget_omits_native_scope(
    tmp_path: Path,
    monkeypatch,
):
    repository = _repository(tmp_path)
    called = False

    def fake_run(repository_path, options):
        nonlocal called
        called = True
        raise AssertionError("OCR adapter must not run outside deterministic context")

    monkeypatch.setattr("before_deploy.ocr_provider.run_ocr_advisory", fake_run)
    provider = OcrAdvisoryProvider()

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(
            repository=repository,
            max_file_bytes=1000,
            max_context_bytes=1,
            from_ref="HEAD^",
            to_ref="HEAD",
        ),
    )

    assert called is False
    assert result.status == "ERROR"
    assert result.findings == ()
    assert result.scope_status == "CONTEXT_LIMITED"
    assert "could not be proven equal" in (result.scope_message or "")


def test_ocr_provider_identity_is_stable():
    identity = OcrAdvisoryProvider().identity

    assert identity.provider_id == "ocr"
    assert identity.input_name == "ocr"
    assert identity.source == "open-code-review"
    assert identity.source_format == "ocr-json"
