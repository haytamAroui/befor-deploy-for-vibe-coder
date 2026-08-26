"""Offline GitHub artifact-attestation verification adapter."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.controls.external import (
    ExternalToolConfig,
    ExternalToolRunner,
    read_bounded_report,
)
from before_deploy.models import ControlExecution, ExecutionStatus, utc_now
from before_deploy.policy import ProvenancePolicy


class ProvenanceControl:
    """Verify a local release artifact against a downloaded GitHub attestation bundle."""

    control_id = "SEC-PROVENANCE-001"
    control_version = "0.1.0"

    def __init__(
        self,
        config: ExternalToolConfig,
        provenance_policy: ProvenancePolicy,
        runner: ExternalToolRunner | None = None,
    ) -> None:
        self._config = config
        self._provenance_policy = provenance_policy
        self._runner = runner or ExternalToolRunner()

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        artifact = context.repository_root / self._provenance_policy.artifact_path
        bundle = context.repository_root / self._provenance_policy.bundle_path
        if not artifact.is_file():
            return _error_result(self, started_at, "ARTIFACT_NOT_FOUND")
        if not bundle.is_file():
            return _error_result(self, started_at, "ATTESTATION_BUNDLE_NOT_FOUND")

        with tempfile.TemporaryDirectory(prefix="before-deploy-provenance-") as temporary_dir:
            output_path = Path(temporary_dir) / "verification.json"
            process = self._runner.run(
                config=self._config,
                arguments=(
                    "attestation",
                    "verify",
                    artifact.as_posix(),
                    "--bundle",
                    bundle.as_posix(),
                    "--repo",
                    self._provenance_policy.repository,
                    "--signer-workflow",
                    self._provenance_policy.signer_workflow,
                    "--predicate-type",
                    "https://slsa.dev/provenance/v1",
                    "--deny-self-hosted-runners",
                    "--format",
                    "json",
                ),
                cwd=context.repository_root,
                stdout_path=output_path,
            )
            if not process.completed:
                return _error_result(self, started_at, process.error_kind or "PROCESS_FAILURE")
            if process.return_code != 0:
                return _error_result(self, started_at, f"VERIFICATION_EXIT_{process.return_code}")
            try:
                raw_output = read_bounded_report(output_path, self._config.max_report_bytes)
                verifications = json.loads(raw_output.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return _error_result(self, started_at, "INVALID_VERIFICATION_OUTPUT")
            if not _has_required_verified_evidence(verifications):
                return _error_result(self, started_at, "VERIFIED_EVIDENCE_MISSING")

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Artifact provenance was verified against the configured signed attestation bundle.",
                metadata={
                    "adapter": "gh-attestation",
                    "tool_version": self._config.tool_version,
                    "expected_repository": self._provenance_policy.repository,
                    "expected_signer_workflow": self._provenance_policy.signer_workflow,
                    "verified_attestation_count": str(len(verifications)),
                },
            ),
            findings=(),
        )


def _has_required_verified_evidence(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if not isinstance(item, dict):
            return False
        verification = item.get("verificationResult")
        if not isinstance(verification, dict):
            return False
        signature = verification.get("signature")
        timestamps = verification.get("verifiedTimestamps")
        if not isinstance(signature, dict) or not signature.get("certificate"):
            return False
        if not isinstance(timestamps, list) or not timestamps:
            return False
    return True


def _error_result(control: ProvenanceControl, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Provenance verification adapter error: {error_kind}",
            metadata={
                "adapter": "gh-attestation",
                "tool_version": control._config.tool_version,
                "error_kind": error_kind,
            },
        )
    )
