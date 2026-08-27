"""Optional isolated Gosec adapter with fixed arguments and redacted findings."""

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


class GosecControl:
    """Run preinstalled Gosec locally without AI, target configuration, or module downloads."""

    control_id = "SEC-GOSEC-001"
    control_version = "0.1.0"

    def __init__(self, config: ExternalToolConfig, runner: ExternalToolRunner | None = None) -> None:
        self._config = config
        self._runner = runner or ExternalToolRunner()

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        with tempfile.TemporaryDirectory(prefix="before-deploy-gosec-") as temporary_dir:
            report_path = Path(temporary_dir) / "gosec.json"
            process = self._runner.run(
                config=self._config,
                arguments=(
                    "-fmt=json",
                    "-out",
                    report_path.as_posix(),
                    "-no-fail",
                    "-exclude-generated",
                    "-nosec=true",
                    "-nosec-require-rules",
                    "-nosec-require-justification",
                    "./...",
                ),
                cwd=context.repository_root,
                environment_overrides={
                    "GOFLAGS": "-mod=readonly",
                    "GONOSUMDB": "*",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GIT_TERMINAL_PROMPT": "0",
                },
            )
            if not process.completed:
                return _error_result(self, started_at, process.error_kind or "PROCESS_FAILURE")
            if process.return_code != 0:
                return _error_result(self, started_at, f"UNEXPECTED_EXIT_{process.return_code}")
            try:
                document = json.loads(
                    read_bounded_report(report_path, self._config.max_report_bytes).decode("utf-8")
                )
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return _error_result(self, started_at, "INVALID_REPORT")
            if not isinstance(document, dict):
                return _error_result(self, started_at, "INVALID_REPORT_SHAPE")
            if _scanner_reported_errors(document.get("Golang errors")):
                return _error_result(self, started_at, "SCANNER_REPORTED_ERRORS")
            issues = document.get("Issues", [])
            if issues is None:
                issues = []
            if not isinstance(issues, list):
                return _error_result(self, started_at, "INVALID_REPORT_SHAPE")
            try:
                findings = tuple(_normalize_issue(self, context.repository_root, issue) for issue in issues)
            except ValueError:
                return _error_result(self, started_at, "INVALID_FINDING_RECORD")
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    f"Normalized {len(findings)} Gosec findings without retaining upstream source, details, "
                    "or suppression text."
                ),
                metadata={
                    "adapter": "gosec",
                    "tool_version": self._config.tool_version,
                    "exit_code": str(process.return_code),
                    "module_network": "disabled",
                },
            ),
            findings=findings,
        )


def _normalize_issue(control: GosecControl, root: Path, issue: Any) -> Finding:
    if not isinstance(issue, dict):
        raise ValueError("Gosec issue must be an object")
    upstream_rule = _required_string(issue, "rule_id")
    raw_path = _required_string(issue, "file")
    raw_line = issue.get("line")
    line = _positive_line(raw_line)
    upstream_severity = _required_string(issue, "severity")
    upstream_confidence = _required_string(issue, "confidence")
    location = Location(path=_repository_relative_path(root, raw_path), start_line=line)
    evidence = {
        "upstream_rule_id": upstream_rule,
        "upstream_severity": upstream_severity.upper(),
        "upstream_confidence": upstream_confidence.upper(),
    }
    cwe = issue.get("cwe")
    if isinstance(cwe, dict) and isinstance(cwe.get("id"), str) and cwe["id"].strip():
        evidence["upstream_cwe_id"] = cwe["id"].strip()
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title=f"Gosec rule matched: {upstream_rule}",
        message=(
            "Gosec reported a potential Go security issue. Upstream source excerpts, details, code, "
            "and suppression text were discarded before normalization."
        ),
        remediation="Review the upstream Gosec rule and the affected code path, then remediate or use a policy waiver.",
        severity=_severity_from_gosec(upstream_severity),
        confidence=_confidence_from_gosec(upstream_confidence),
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _scanner_reported_errors(value: Any) -> bool:
    """Treat any non-empty upstream compiler/scanner error field as a failed analysis."""
    return value not in (None, "", [], {})


def _required_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Gosec issue field {key} must be a non-empty string")
    return value.strip()


def _positive_line(value: Any) -> int:
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return int(value)
    raise ValueError("Gosec issue line must be a positive integer or decimal string")


def _repository_relative_path(root: Path, raw_path: str) -> str:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError as error:
            raise ValueError("Gosec finding path escaped repository root") from error
    if any(part == ".." for part in candidate.parts):
        raise ValueError("Gosec finding path escaped repository root")
    return candidate.as_posix()


def _severity_from_gosec(value: str) -> Severity:
    normalized = value.upper()
    if normalized in {"CRITICAL", "BLOCKER"}:
        return Severity.BLOCKER
    if normalized == "HIGH":
        return Severity.HIGH
    if normalized == "MEDIUM":
        return Severity.MEDIUM
    return Severity.LOW


def _confidence_from_gosec(value: str) -> Confidence:
    normalized = value.upper()
    if normalized == "HIGH":
        return Confidence.HIGH
    if normalized == "MEDIUM":
        return Confidence.MEDIUM
    return Confidence.LOW


def _error_result(control: GosecControl, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Gosec adapter error: {error_kind}",
            metadata={
                "adapter": "gosec",
                "tool_version": control._config.tool_version,
                "error_kind": error_kind,
                "module_network": "disabled",
            },
        )
    )
