"""Release-profile check for a minimally valid CycloneDX SBOM."""

from __future__ import annotations

import json

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import (
    Confidence,
    ControlExecution,
    ExecutionStatus,
    Finding,
    Location,
    Severity,
    fingerprint_for,
    utc_now,
)


class CycloneDxSbomControl:
    """Verify that a bounded repository contains a parseable CycloneDX JSON SBOM."""

    control_id = "SEC-RELEASE-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        candidates = [
            path
            for path in context.inventory.files
            if path.name == "bom.json" or path.name.endswith(".cdx.json")
        ]
        if not candidates:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.COMPLETED,
                    started_at=started_at,
                    completed_at=utc_now(),
                    message="No CycloneDX JSON SBOM candidate was found.",
                ),
                findings=(self._missing_finding(),),
            )

        findings: list[Finding] = []
        valid = False
        for candidate in candidates:
            relative = candidate.relative_to(context.repository_root).as_posix()
            try:
                document = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError(f"Unable to parse SBOM candidate: {relative}") from error
            if isinstance(document, dict) and document.get("bomFormat") == "CycloneDX":
                valid = True
                continue
            location = Location(path=relative)
            evidence = {"path": relative, "issue": "not_cyclonedx"}
            findings.append(
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="SBOM candidate is not a CycloneDX document",
                    message="A release SBOM candidate exists but does not declare bomFormat: CycloneDX.",
                    remediation="Generate a CycloneDX JSON SBOM from the release dependency graph.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    fingerprint=fingerprint_for(self.control_id, location, evidence),
                    location=location,
                    evidence=evidence,
                )
            )
        if not valid:
            findings.append(self._missing_finding())
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Validated {len(candidates)} CycloneDX SBOM candidate files.",
            ),
            findings=tuple(findings),
        )

    def _missing_finding(self) -> Finding:
        evidence = {"issue": "cyclonedx_sbom_missing"}
        return Finding(
            rule_id=self.control_id,
            rule_version=self.control_version,
            title="CycloneDX SBOM is missing",
            message="No parseable CycloneDX JSON software bill of materials was found in the release scope.",
            remediation="Generate a CycloneDX SBOM during the release build and retain it with the artifact.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            fingerprint=fingerprint_for(self.control_id, None, evidence),
            location=None,
            evidence=evidence,
        )
