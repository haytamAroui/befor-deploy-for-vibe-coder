from __future__ import annotations

from pathlib import Path

from before_deploy.advisory import AdvisoryImport
from before_deploy.advisory_provider import AdvisoryProviderRequest, execute_advisory_provider
from before_deploy.ocr_advisory import OCR_SOURCE, OCR_SOURCE_FORMAT
from before_deploy.ocr_provider import OcrAdvisoryProvider


def test_ocr_provider_maps_generic_request_to_existing_adapter(tmp_path: Path, monkeypatch):
    captured = {}

    def fake_run(repository, options):
        captured["repository"] = repository
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
        repository=tmp_path,
        max_file_bytes=654_321,
        from_ref="main",
        to_ref="HEAD",
    )

    result = execute_advisory_provider(provider, request)

    options = captured["options"]
    assert captured["repository"] == tmp_path.resolve()
    assert options.timeout_seconds == 45
    assert options.max_output_bytes == 123_456
    assert options.max_file_bytes == 654_321
    assert options.from_ref == "main"
    assert options.to_ref == "HEAD"
    assert options.commit is None
    assert result.input_name == "ocr"
    assert result.source == OCR_SOURCE
    assert result.source_format == OCR_SOURCE_FORMAT
    assert result.scope_status == "MATCHED"


def test_ocr_provider_identity_is_stable():
    identity = OcrAdvisoryProvider().identity

    assert identity.provider_id == "ocr"
    assert identity.input_name == "ocr"
    assert identity.source == "open-code-review"
    assert identity.source_format == "ocr-json"
