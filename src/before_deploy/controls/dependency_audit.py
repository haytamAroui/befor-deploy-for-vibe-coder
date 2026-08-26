"""Deterministic pip-audit adapter for known Python dependency vulnerabilities."""

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
    Severity,
    fingerprint_for,
    utc_now,
)
from before_deploy.policy import DependencyAuditPolicy


class DependencyAuditControl:
    """Audit declared Python dependencies without installing target-project packages."""

    control_id = "SEC-DEP-VULN-001"
    control_version = "0.1.0"

    def __init__(
        self,
        config: ExternalToolConfig,
        audit_policy: DependencyAuditPolicy,
        uv_config: ExternalToolConfig | None = None,
        runner: ExternalToolRunner | None = None,
    ) -> None:
        self._config = config
        self._audit_policy = audit_policy
        self._uv_config = uv_config
        self._runner = runner or ExternalToolRunner()

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        with tempfile.TemporaryDirectory(prefix="before-deploy-dependency-audit-") as temporary_dir:
            temporary_path = Path(temporary_dir)
            requirements_path, preparation_error = self._requirements_input(
                context.repository_root, temporary_path
            )
            if preparation_error:
                return _error_result(self, started_at, preparation_error)
            assert requirements_path is not None
            report_path = temporary_path / "pip-audit.json"
            process = self._runner.run(
                config=self._config,
                arguments=(
                    "--requirement",
                    requirements_path.as_posix(),
                    "--no-deps",
                    "--strict",
                    "--format",
                    "json",
                    "--output",
                    report_path.as_posix(),
                ),
                cwd=context.repository_root,
            )
            if not process.completed:
                return _error_result(self, started_at, process.error_kind or "PROCESS_FAILURE")
            if process.return_code not in {0, 1}:
                return _error_result(self, started_at, f"UNEXPECTED_EXIT_{process.return_code}")
            try:
                raw_report = read_bounded_report(report_path, self._config.max_report_bytes)
                dependencies = json.loads(raw_report.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return _error_result(self, started_at, "INVALID_REPORT")
            if not isinstance(dependencies, list):
                return _error_result(self, started_at, "INVALID_REPORT_SHAPE")
            try:
                findings = tuple(
                    finding
                    for dependency in dependencies
                    for finding in _normalize_dependency(self, dependency)
                )
            except ValueError:
                return _error_result(self, started_at, "INVALID_VULNERABILITY_RECORD")
            if (process.return_code == 0 and findings) or (process.return_code == 1 and not findings):
                return _error_result(self, started_at, "EXIT_REPORT_CONTRADICTION")

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Normalized {len(findings)} known dependency vulnerabilities.",
                metadata={
                    "adapter": "pip-audit",
                    "tool_version": self._config.tool_version,
                    "input": self._audit_policy.input_kind,
                    "exit_code": str(process.return_code),
                },
            ),
            findings=findings,
        )

    def _requirements_input(
        self, repository_root: Path, temporary_path: Path
    ) -> tuple[Path | None, str | None]:
        if self._audit_policy.input_kind == "requirements":
            assert self._audit_policy.requirements_path is not None
            path = repository_root / self._audit_policy.requirements_path
            if not path.is_file():
                return None, "REQUIREMENTS_FILE_NOT_FOUND"
            return path, None
        if self._uv_config is None:
            return None, "UV_CONFIGURATION_MISSING"
        if not (repository_root / "uv.lock").is_file():
            return None, "UV_LOCK_NOT_FOUND"
        requirements_path = temporary_path / "requirements.txt"
        export = self._runner.run(
            config=self._uv_config,
            arguments=(
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--format",
                "requirements-txt",
                "--output-file",
                requirements_path.as_posix(),
            ),
            cwd=repository_root,
        )
        if not export.completed:
            return None, f"UV_EXPORT_{export.error_kind or 'PROCESS_FAILURE'}"
        if export.return_code != 0 or not requirements_path.is_file():
            return None, "UV_EXPORT_FAILED"
        return requirements_path, None


def _normalize_dependency(control: DependencyAuditControl, dependency: Any) -> tuple[Finding, ...]:
    if not isinstance(dependency, dict):
        raise ValueError("Dependency record must be an object")
    package_name = _required_string(dependency, "name")
    package_version = _required_string(dependency, "version")
    vulnerabilities = dependency.get("vulns")
    if not isinstance(vulnerabilities, list):
        raise ValueError("Dependency vulnerabilities must be a list")
    findings: list[Finding] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise ValueError("Vulnerability record must be an object")
        vulnerability_id = _required_string(vulnerability, "id")
        aliases = _string_list(vulnerability.get("aliases", []), "aliases")
        fix_versions = _string_list(vulnerability.get("fix_versions", []), "fix_versions")
        evidence = {
            "package": package_name,
            "package_version": package_version,
            "vulnerability_id": vulnerability_id,
            "aliases": ",".join(sorted(aliases)),
            "fix_versions": ",".join(sorted(fix_versions)),
        }
        remediation = (
            f"Upgrade {package_name} to one of the reported fixed versions: {', '.join(fix_versions)}."
            if fix_versions
            else f"Review {vulnerability_id} for {package_name} and apply an approved mitigation or waiver."
        )
        findings.append(
            Finding(
                rule_id=control.control_id,
                rule_version=control.control_version,
                title=f"Known dependency vulnerability: {vulnerability_id}",
                message=(
                    f"{package_name} {package_version} is reported with advisory {vulnerability_id}. "
                    "The report intentionally omits verbose advisory descriptions."
                ),
                remediation=remediation,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint=fingerprint_for(control.control_id, None, evidence),
                evidence=evidence,
            )
        )
    return tuple(findings)


def _error_result(
    control: DependencyAuditControl, started_at, error_kind: str
) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Dependency audit adapter error: {error_kind}",
            metadata={
                "adapter": "pip-audit",
                "tool_version": control._config.tool_version,
                "error_kind": error_kind,
            },
        )
    )


def _required_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Field {key} must be a non-empty string")
    return value


def _string_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"Field {field_name} must be a list of non-empty strings")
    return tuple(value)
