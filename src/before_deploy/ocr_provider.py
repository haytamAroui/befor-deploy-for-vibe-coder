"""OpenCodeReview implementation of the generic advisory provider contract."""

from __future__ import annotations

from dataclasses import dataclass

from before_deploy.advisory import AdvisoryImport, advisory_error_import
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
from before_deploy.review_preview import build_review_preview


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
        context = request.context
        if context is None:
            return _context_error("OCR provider received no deterministic advisory context")

        preview = build_review_preview(
            request.repository,
            max_file_bytes=request.max_file_bytes,
            from_ref=request.from_ref,
            to_ref=request.to_ref,
            commit=request.commit,
        )
        preview_paths = {entry.path for entry in preview.entries if entry.will_review}
        context_paths = {entry.path for entry in context.manifest.selected}
        if context_paths != preview_paths:
            omitted = preview_paths - context_paths
            unexpected = context_paths - preview_paths
            return _context_error(
                "OCR cannot honor the deterministic advisory context without changing its "
                f"selected-file set (omitted={len(omitted)}, unexpected={len(unexpected)})"
            )

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


def _context_error(message: str) -> AdvisoryImport:
    return advisory_error_import(
        input_name="ocr",
        source=OCR_SOURCE,
        source_format=OCR_SOURCE_FORMAT,
        message=message,
        scope_status="CONTEXT_LIMITED",
        scope_message=(
            "OCR was not started because its native selection could not be proven equal to "
            "the deterministic advisory context"
        ),
    )
