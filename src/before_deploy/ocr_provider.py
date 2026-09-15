"""OpenCodeReview implementation of the generic advisory provider contract."""

from __future__ import annotations

from dataclasses import dataclass

from before_deploy.advisory import AdvisoryImport, advisory_error_import
from before_deploy.advisory_execution import (
    MODEL_IDENTITY_UNATTESTED,
    AdvisoryExecutionBudget,
    AdvisoryExecutionDescriptor,
    AdvisoryExecutionParameter,
    AdvisoryModelIdentity,
)
from before_deploy.advisory_provider import (
    AdvisoryProviderIdentity,
    AdvisoryProviderRequest,
)
from before_deploy.ocr_advisory import (
    OCR_MANIFEST_SCHEMA,
    OCR_PREVIEW_TIMEOUT_SECONDS,
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

    def execution_descriptor(self, request: AdvisoryProviderRequest) -> AdvisoryExecutionDescriptor:
        """Declare redaction-safe OCR execution metadata without inventing model identity."""
        return AdvisoryExecutionDescriptor(
            implementation="open-code-review-cli",
            implementation_version=None,
            model=AdvisoryModelIdentity(
                status=MODEL_IDENTITY_UNATTESTED,
                reason=(
                    "The current OCR JSON contract does not attest the configured LLM provider/model"
                ),
            ),
            configuration=(
                AdvisoryExecutionParameter(name="adapter_contract", value="before-deploy-ocr-v1"),
                AdvisoryExecutionParameter(name="audience", value="agent"),
                AdvisoryExecutionParameter(name="format", value="json"),
                AdvisoryExecutionParameter(name="manifest_schema", value=OCR_MANIFEST_SCHEMA),
            ),
            budgets=(
                AdvisoryExecutionBudget(
                    name="max_output_bytes",
                    limit=self.max_output_bytes,
                    unit="bytes",
                ),
                AdvisoryExecutionBudget(
                    name="preview_timeout_seconds",
                    limit=min(self.timeout_seconds, OCR_PREVIEW_TIMEOUT_SECONDS),
                    unit="seconds",
                ),
                AdvisoryExecutionBudget(
                    name="review_timeout_seconds",
                    limit=self.timeout_seconds,
                    unit="seconds",
                ),
            ),
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
