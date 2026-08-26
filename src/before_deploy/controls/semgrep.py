"""Semgrep local-rule adapter with explicit privacy and execution boundaries."""

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


class SemgrepControl:
    """Run checked-in Semgrep rules without remote registry, autofix, or local builds."""

    control_id = "SEC-SAST-SEMGREP-001"
    control_version = "0.1.0"

    def __init__(
        self,
        config: ExternalToolConfig,
        rule_directory: Path,
        runner: ExternalToolRunner | None = None,
    ) -> None:
        self._config = config
        self._rule_directory = rule_directory.resolve()
        self._runner = runner or ExternalToolRunner()

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        if not self._rule_directory.is_dir():
            return _error_result(self, started_at, "RULE_DIRECTORY_NOT_FOUND")
        with tempfile.TemporaryDirectory(prefix="before-deploy-semgrep-") as temporary_dir:
            report_path = Path(temporary_dir) / "semgrep.json"
            arguments = (
                "scan",
                "--config",
                self._rule_directory.as_posix(),
                "--json",
                "--json-output",
                report_path.as_posix(),
                "--metrics=off",
                "--disable-version-check",
                "--no-autofix",
                "--max-target-bytes",
                str(self._config.max_report_bytes),
                ".",
            )
            process = self._runner.run(
                config=self._config,
                arguments=arguments,
                cwd=context.repository_root,
            )
            if not process.completed:
                return _error_result(self, started_at, process.error_kind or "PROCESS_FAILURE")
            if process.return_code != 0:
                return _error_result(self, started_at, f"UNEXPECTED_EXIT_{process.return_code}")
            try:
                raw_report = read_bounded_report(report_path, self._config.max_report_bytes)
                document = json.loads(raw_report.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return _error_result(self, started_at, "INVALID_REPORT")
            if not isinstance(document, dict):
                return _error_result(self, started_at, "INVALID_REPORT_SHAPE")
            results = document.get("results")
            errors = document.get("errors", [])
            if not isinstance(results, list) or not isinstance(errors, list):
                return _error_result(self, started_at, "INVALID_REPORT_SHAPE")
            if errors:
                return _error_result(self, started_at, "SCANNER_REPORTED_ERRORS")
            try:
                findings = tuple(_normalize_result(self, context.repository_root, item) for item in results)
            except ValueError:
                return _error_result(self, started_at, "INVALID_FINDING_RECORD")

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Normalized {len(findings)} Semgrep findings from local rules.",
                metadata={
                    "adapter": "semgrep",
                    "tool_version": self._config.tool_version,
                    "exit_code": str(process.return_code),
                },
            ),
            findings=findings,
        )


def _normalize_result(control: SemgrepControl, root: Path, result: Any) -> Finding:
    if not isinstance(result, dict):
        raise ValueError("Semgrep result must be an object")
    check_id = _required_string(result, "check_id")
    raw_path = _required_string(result, "path")
    start = result.get("start")
    extra = result.get("extra")
    if not isinstance(start, dict) or not isinstance(start.get("line"), int) or start["line"] <= 0:
        raise ValueError("Semgrep result start line must be a positive integer")
    if not isinstance(extra, dict):
        raise ValueError("Semgrep result extra must be an object")
    severity = _severity_from_semgrep(extra.get("severity"))
    location = Location(path=_repository_relative_path(root, raw_path), start_line=start["line"])
    evidence = {"upstream_rule_id": check_id, "upstream_severity": str(extra.get("severity", "UNKNOWN"))}
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title=f"Semgrep rule matched: {check_id}",
        message=(
            "A checked-in Semgrep rule matched this source location. Raw source excerpts and tool output "
            "are intentionally not copied into the normalized finding."
        ),
        remediation="Review the checked-in Semgrep rule and remediate the matching code path.",
        severity=severity,
        confidence=Confidence.MEDIUM,
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _error_result(control: SemgrepControl, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Semgrep adapter error: {error_kind}",
            metadata={
                "adapter": "semgrep",
                "tool_version": control._config.tool_version,
                "error_kind": error_kind,
            },
        )
    )


def _required_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Semgrep finding field {key} must be a non-empty string")
    return value


def _repository_relative_path(root: Path, raw_path: str) -> str:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError as error:
            raise ValueError("Semgrep finding path escaped repository root") from error
    if any(part == ".." for part in candidate.parts):
        raise ValueError("Semgrep finding path escaped repository root")
    return candidate.as_posix()


def _severity_from_semgrep(value: Any) -> Severity:
    if value == "ERROR":
        return Severity.HIGH
    if value == "WARNING":
        return Severity.MEDIUM
    return Severity.LOW
