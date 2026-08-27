from __future__ import annotations

import json
import re
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


_INLINE_IGNORE_PATTERN = re.compile(r"trivy\s*:\s*ignore\s*:[^\r\n]*", re.IGNORECASE)
_VERSION_PATTERN = re.compile(r"^Version:\s*(v?[0-9]+(?:\.[0-9]+){1,3})\s*$", re.MULTILINE)
_MAX_VERSION_BYTES = 4096
_SUPPORTED_TYPES = frozenset({"dockerfile", "terraform"})


class TrivyConfigControl:
    """Run a preinstalled Trivy config scan only over staged Dockerfile and Terraform inputs."""

    control_id = "SEC-TRIVY-CONFIG-001"
    control_version = "0.1.0"

    def __init__(self, config: ExternalToolConfig, runner: ExternalToolRunner | None = None) -> None:
        self._config = config
        self._runner = runner or ExternalToolRunner()

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        source_paths = _eligible_source_paths(context)
        if not source_paths:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message=(
                        "No inventory-included Dockerfile, Containerfile, or Terraform configuration was "
                        "available for the isolated Trivy adapter."
                    ),
                    metadata=_execution_metadata(self._config),
                )
            )

        with tempfile.TemporaryDirectory(prefix="before-deploy-trivy-config-") as temporary_dir:
            temporary_root = Path(temporary_dir)
            stage_root = temporary_root / "stage"
            report_path = temporary_root / "trivy.json"
            version_path = temporary_root / "trivy-version.txt"
            ignore_path = temporary_root / "empty.trivyignore"
            cache_dir = temporary_root / "cache"
            module_dir = temporary_root / "modules"
            try:
                staged_paths = _stage_sources(
                    repository_root=context.repository_root,
                    source_paths=source_paths,
                    stage_root=stage_root,
                )
                ignore_path.write_text("", encoding="utf-8")
                cache_dir.mkdir()
                module_dir.mkdir()
            except ValueError as error:
                return _error_result(self, started_at, str(error))
            except OSError:
                return _error_result(self, started_at, "STAGING_FAILURE")

            version_process = self._runner.run(
                config=self._config,
                arguments=("--version",),
                cwd=stage_root,
                stdout_path=version_path,
            )
            if not version_process.completed:
                return _error_result(self, started_at, version_process.error_kind or "VERSION_PROCESS_FAILURE")
            if version_process.return_code != 0:
                return _error_result(self, started_at, f"VERSION_UNEXPECTED_EXIT_{version_process.return_code}")
            try:
                reported_version = _parse_version(
                    read_bounded_report(version_path, min(self._config.max_report_bytes, _MAX_VERSION_BYTES))
                )
            except (UnicodeDecodeError, ValueError):
                return _error_result(self, started_at, "INVALID_VERSION_REPORT")
            if _normalized_version(reported_version) != _normalized_version(self._config.tool_version):
                return _error_result(self, started_at, "VERSION_MISMATCH")

            process = self._runner.run(
                config=self._config,
                arguments=(
                    "config",
                    "--format",
                    "json",
                    "--output",
                    report_path.as_posix(),
                    "--scanners",
                    "misconfig",
                    "--misconfig-scanners",
                    "dockerfile,terraform",
                    "--offline-scan",
                    "--skip-check-update",
                    "--skip-version-check",
                    "--disable-telemetry",
                    "--skip-vex-repo-update",
                    "--tf-exclude-downloaded-modules",
                    "--ignorefile",
                    ignore_path.as_posix(),
                    "--cache-dir",
                    cache_dir.as_posix(),
                    "--module-dir",
                    module_dir.as_posix(),
                    stage_root.as_posix(),
                ),
                cwd=stage_root,
            )
            if not process.completed:
                return _error_result(self, started_at, process.error_kind or "PROCESS_FAILURE")
            if process.return_code != 0:
                return _error_result(self, started_at, f"UNEXPECTED_EXIT_{process.return_code}")
            try:
                document = json.loads(
                    read_bounded_report(report_path, self._config.max_report_bytes).decode("utf-8")
                )
                findings = _normalize_document(self, document, stage_root, staged_paths)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                return _error_result(self, started_at, "INVALID_REPORT")

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    f"Normalized {len(findings)} Trivy configuration findings from an isolated staged copy; "
                    "upstream messages, causes, resource identifiers, URLs, snippets, and suppressions were discarded."
                ),
                metadata={
                    **_execution_metadata(self._config),
                    "exit_code": str(process.return_code),
                    "staged_file_count": str(len(staged_paths)),
                    "version_verified": "true",
                },
            ),
            findings=findings,
        )


def _eligible_source_paths(context: ControlContext) -> tuple[Path, ...]:
    return tuple(
        path
        for path in context.inventory.files
        if _artifact_category(path.relative_to(context.repository_root)) is not None
    )


def _stage_sources(
    *, repository_root: Path, source_paths: tuple[Path, ...], stage_root: Path
) -> dict[Path, Path]:
    root = repository_root.resolve()
    staged_paths: dict[Path, Path] = {}
    for source_path in source_paths:
        try:
            relative_path = source_path.relative_to(repository_root)
            resolved_source = source_path.resolve(strict=True)
            resolved_source.relative_to(root)
        except (OSError, ValueError) as error:
            raise ValueError("SOURCE_PATH_ESCAPES_REPOSITORY") from error
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("SOURCE_PATH_ESCAPES_REPOSITORY")
        if _artifact_category(relative_path) is None:
            raise ValueError("UNSUPPORTED_STAGED_ARTIFACT")
        destination = stage_root / relative_path
        try:
            destination.resolve().relative_to(stage_root.resolve())
        except ValueError as error:
            raise ValueError("STAGE_PATH_ESCAPES_ROOT") from error
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = source_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("STAGED_CONFIGURATION_NOT_UTF8") from error
        destination.write_text(_neutralize_inline_ignores(content), encoding="utf-8")
        staged_paths[relative_path] = destination
    return staged_paths


def _neutralize_inline_ignores(content: str) -> str:
    """Preserve line positions while making target-controlled Trivy ignore directives inert."""

    def replacement(match: re.Match[str]) -> str:
        prefix = "trivy-neutralized"
        return prefix + " " * max(0, len(match.group(0)) - len(prefix))

    return _INLINE_IGNORE_PATTERN.sub(replacement, content)


def _parse_version(raw: bytes) -> str:
    decoded = raw.decode("utf-8")
    match = _VERSION_PATTERN.search(decoded)
    if match is None:
        raise ValueError("Trivy version output was not recognized")
    return match.group(1)


def _normalized_version(value: str) -> str:
    return value.strip().lower().removeprefix("v")


def _normalize_document(
    control: TrivyConfigControl,
    document: Any,
    stage_root: Path,
    staged_paths: dict[Path, Path],
) -> tuple[Finding, ...]:
    if not isinstance(document, dict):
        raise ValueError("Trivy report must be an object")
    if not isinstance(document.get("SchemaVersion"), int) or document["SchemaVersion"] <= 0:
        raise ValueError("Trivy report schema version was not recognized")
    results = document.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy report Results must be a list")

    normalized: dict[str, Finding] = {}
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy result must be an object")
        target = _result_target(result, stage_root, staged_paths)
        category = _required_string(result, "Type").lower()
        if category not in _SUPPORTED_TYPES:
            raise ValueError("Trivy result type is outside the configured adapter scope")
        if category != _artifact_category(target):
            raise ValueError("Trivy result type does not match its staged artifact")
        if result.get("Class") != "config":
            raise ValueError("Trivy result class was not configuration scanning")
        misconfigurations = result.get("Misconfigurations", [])
        if misconfigurations is None:
            misconfigurations = []
        if not isinstance(misconfigurations, list):
            raise ValueError("Trivy misconfigurations must be a list")
        for record in misconfigurations:
            finding = _normalize_record(control, record, target, category)
            normalized[finding.fingerprint] = finding
    return tuple(normalized[fingerprint] for fingerprint in sorted(normalized))


def _result_target(result: dict[str, Any], stage_root: Path, staged_paths: dict[Path, Path]) -> Path:
    raw_target = _required_string(result, "Target")
    candidate = Path(raw_target)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(stage_root.resolve())
        except ValueError as error:
            raise ValueError("Trivy target path escaped staged root") from error
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Trivy target path escaped staged root")
    normalized = Path(candidate.as_posix())
    if normalized not in staged_paths:
        raise ValueError("Trivy target was not a staged artifact")
    return normalized


def _normalize_record(
    control: TrivyConfigControl, record: Any, target: Path, category: str
) -> Finding:
    if not isinstance(record, dict):
        raise ValueError("Trivy misconfiguration must be an object")
    upstream_rule_id = _safe_rule_id(_required_string(record, "ID"))
    upstream_severity = _required_string(record, "Severity").upper()
    cause_metadata = record.get("CauseMetadata")
    if not isinstance(cause_metadata, dict):
        raise ValueError("Trivy misconfiguration lacks cause metadata")
    line = _positive_line(cause_metadata.get("StartLine"))
    location = Location(path=target.as_posix(), start_line=line)
    evidence = {
        "upstream_rule_id": upstream_rule_id,
        "upstream_severity": upstream_severity,
        "artifact_category": category,
    }
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title=f"Trivy configuration rule matched: {upstream_rule_id}",
        message=(
            "Trivy reported a configuration misconfiguration in an isolated staged artifact. Upstream messages, "
            "causes, resource identifiers, URLs, snippets, and suppression text were discarded before normalization."
        ),
        remediation="Review the upstream Trivy rule against the staged configuration, remediate it, or use a policy waiver.",
        severity=_severity_from_trivy(upstream_severity),
        confidence=Confidence.HIGH,
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _artifact_category(relative_path: Path) -> str | None:
    name = relative_path.name.lower()
    if name.startswith("dockerfile") or name.startswith("containerfile"):
        return "dockerfile"
    if relative_path.suffix.lower() == ".tf":
        return "terraform"
    return None


def _required_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Trivy record field {key} must be a non-empty string")
    return value.strip()


def _safe_rule_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise ValueError("Trivy rule ID contains unsupported characters")
    return value


def _positive_line(value: Any) -> int:
    if isinstance(value, int) and value > 0:
        return value
    raise ValueError("Trivy finding line must be a positive integer")


def _severity_from_trivy(value: str) -> Severity:
    if value == "CRITICAL":
        return Severity.BLOCKER
    if value == "HIGH":
        return Severity.HIGH
    if value == "MEDIUM":
        return Severity.MEDIUM
    if value in {"LOW", "UNKNOWN"}:
        return Severity.LOW
    raise ValueError("Trivy severity was not recognized")


def _execution_metadata(config: ExternalToolConfig) -> dict[str, str]:
    return {
        "adapter": "trivy-config",
        "tool_version": config.tool_version,
        "network_mode": "offline-fixed-arguments",
        "suppression_mode": "policy-waivers-only",
    }


def _error_result(control: TrivyConfigControl, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Trivy configuration adapter error: {error_kind}",
            metadata={
                **_execution_metadata(control._config),
                "error_kind": error_kind,
            },
        )
    )
