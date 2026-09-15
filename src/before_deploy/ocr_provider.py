"""OpenCodeReview implementation of the generic advisory provider contract."""

from __future__ import annotations

from dataclasses import dataclass

from before_deploy.advisory import AdvisoryImport
from before_deploy.advisory_provider import (
    AdvisoryProviderIdentity,
    AdvisoryProviderRequest,
)
from before_deploy.ocr_advisory import (
    OCR_SOURCE,
    OCR_SOURCE_FORMAT,
    OcrAdvisoryOptions,
    run_ocr_advisory,
)


@dataclass(frozen=True)
class OcrAdvisoryProvider:
    """OCR provider adapter; all output is normalized by the provider runtime."""

    timeout_seconds: int = 900
    max_output_bytes: int = 2_000_000

    @property
    def identity(self) -> AdvisoryProviderIdentity:
        return AdvisoryProviderIdentity(
            provider_id="ocr",
            input_name="ocr",
            source=OCR_SOURCE,
            source_format=OCR_SOURCE_FORMAT,
        )

    def review(self, request: AdvisoryProviderRequest) -> AdvisoryImport:
        return run_ocr_advisory(
            request.repository,
            OcrAdvisoryOptions(
                timeout_seconds=self.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                max_file_bytes=request.max_file_bytes,
                from_ref=request.from_ref,
                to_ref=request.to_ref,
                commit=request.commit,
            ),
        )
