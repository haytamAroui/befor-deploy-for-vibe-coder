"""Gitleaks directory-scan adapter with strict report redaction."""

from __future__ import annotations

import json
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.controls.external import (
    ExternalToolConfig,
    ExternalToolRunner,
    read_bounded_report,
)
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


class GitleaksControl:
    """Run Gitleaks directory scanning without retaining raw secret values."""

    control_id = "SEC-SECRET-GITLEAKS-001"
    control_version = "0.1.0"

    def __init__(self, config: ExternalToolConfig, runner: ExternalToolRunner | None = None) -> None:
        self._config = config
        self._runner = runner or ExternalToolRunner()

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        with tempfile.TemporaryDirectory(prefix="before-deploy-gitleaks-") as temporary_dir:
            report_path = Path(temporary_dir) / "gitleaks.json"
            arguments = (
                "dir",
                "--no-banner",
                "--no-color",
                "--redact=100",
                "--report-format",
                "json",
                "--report-path",
                report_path.as_posix(),
                "--exit-code",
                "1",
                "--timeout",
                str(self._config.timeout_seconds),
                ".",
            )
            process = self._runner.run(
                config=self._config,
                arguments=arguments,
                cwd=context.repository_root,
            )
            if not process.completed:
                return _error_result(self, started_at, process.error_kind or "PROCESS_FAILURE")
            if process.return_code not in {0, 1}:
                return _error_result(self, started_at, f"UNEXPECTED_EXIT_{process.return_code}")
            if process.return_code == 0 and not report_path.exists():
                return _completed_result(self, started_at, (), "No Gitleaks findings were reported.", process)
            try:
                raw_report = read_bounded_report(report_path, self._config.max_report_bytes)
                records = json.loads(raw_report.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return _error_result(self, started_at, "INVALID_REPORT")
            if not isinstance(records, list):
                return _error_result(self, started_at, "INVALID_REPORT_SHAPE")
            if process.return_code == 1 and not records:
                return _error_result(self, started_at, "FINDING_EXIT_WITHOUT_FINDINGS")
            try:
                findings = tuple(_normalize_record(self, context.repository_root, record) for record in records)
            except ValueError:
                return _error_result(self, started_at, "INVALID_FINDING_RECORD")

        return _completed_result(
            self,
            started_at,
            findings,
            f"Normalized {len(findings)} Gitleaks findings without retaining secret values.",
            process,
        )


def _normalize_record(control: GitleaksControl, root: Path, record: Any) -> Finding:
    if not isinstance(record, dict):
        raise ValueError("Gitleaks record must be an object")
    upstream_rule = _required_string(record, "RuleID")
    raw_path = _required_string(record, "File")
    line = record.get("StartLine", record.get("Line"))
    if not isinstance(line, int) or line <= 0:
        raise ValueError("Gitleaks finding line must be a positive integer")
    upstream_fingerprint = _required_string(record, "Fingerprint")
    location = Location(path=_repository_relative_path(root, raw_path), start_line=line)
    evidence = {
        "upstream_rule_id": upstream_rule,
        "upstream_fingerprint_digest": sha256(upstream_fingerprint.encode("utf-8")).hexdigest()[:16],
    }
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title="Secret detected by Gitleaks",
        message=(
            "Gitleaks reported a potential secret. The matched value, matching line, and upstream "
            "secret fields were discarded before normalization."
        ),
        remediation=(
            "Remove and rotate the credential with its issuer, then load any replacement through an approved "
            "secret manager."
        ),
        severity=Severity.BLOCKER,
        confidence=Confidence.HIGH,
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _completed_result(
    control: GitleaksControl,
    started_at,
    findings: tuple[Finding, ...],
    message: str,
    process,
) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.COMPLETED,
            started_at=started_at,
            completed_at=utc_now(),
            message=message,
            metadata={
                "adapter": "gitleaks",
                "tool_version": control._config.tool_version,
                "exit_code": str(process.return_code),
            },
        ),
        findings=findings,
    )


def _error_result(control: GitleaksControl, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Gitleaks adapter error: {error_kind}",
            metadata={
                "adapter": "gitleaks",
                "tool_version": control._config.tool_version,
                "error_kind": error_kind,
            },
        )
    )


def _required_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Gitleaks finding field {key} must be a non-empty string")
    return value


def _repository_relative_path(root: Path, raw_path: str) -> str:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError as error:
            raise ValueError("Gitleaks finding path escaped repository root") from error
    if any(part == ".." for part in candidate.parts):
        raise ValueError("Gitleaks finding path escaped repository root")
    return candidate.as_posix()
