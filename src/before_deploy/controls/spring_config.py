"""Bounded static checks for selected Spring Boot configuration anti-patterns."""

from __future__ import annotations

from pathlib import Path

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

_PROPERTIES_NAMES = {"application.properties", "application-prod.properties"}
_EXPOSURE_KEY = "management.endpoints.web.exposure.include"
_WILDCARD_VALUE = "*"


class SpringActuatorExposureControl:
    """Detect a direct wildcard Spring Boot Actuator web-exposure property."""

    control_id = "SEC-SPRING-ACTUATOR-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        candidates = [
            path
            for path in context.inventory.files
            if path.name in _PROPERTIES_NAMES
            and _is_supported_location(path, context.repository_root)
        ]
        if not candidates:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No supported Spring Boot application.properties file was in scope.",
                )
            )

        findings: list[Finding] = []
        for path in sorted(candidates):
            relative = path.relative_to(context.repository_root).as_posix()
            findings.extend(_find_wildcard_exposure(self, path, relative))

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Inspected {len(candidates)} supported Spring Boot properties file(s).",
            ),
            findings=tuple(findings),
        )


def _is_supported_location(path: Path, repository_root: Path) -> bool:
    relative = path.relative_to(repository_root).as_posix()
    return relative in {
        "application.properties",
        "application-prod.properties",
        "src/main/resources/application.properties",
        "src/main/resources/application-prod.properties",
    }


def _find_wildcard_exposure(
    control: SpringActuatorExposureControl,
    path: Path,
    relative: str,
) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"Unable to read Spring Boot configuration: {relative}") from error

    findings: list[Finding] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        parsed = _parse_property(line)
        if parsed != (_EXPOSURE_KEY, _WILDCARD_VALUE):
            continue

        location = Location(path=relative, start_line=line_number)
        evidence = {
            "artifact": "spring_boot_properties",
            "setting": _EXPOSURE_KEY,
            "value": "wildcard",
        }
        findings.append(
            Finding(
                rule_id=control.control_id,
                rule_version=control.control_version,
                title="Spring Boot Actuator exposes all web endpoints",
                message=(
                    "A supported Spring Boot properties file directly configures Actuator web exposure "
                    "with a wildcard value."
                ),
                remediation=(
                    "Replace wildcard Actuator exposure with an explicit minimum endpoint allowlist and "
                    "verify authentication, authorization, and network exposure in the deployed environment."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint=fingerprint_for(control.control_id, location, evidence),
                location=location,
                evidence=evidence,
            )
        )
    return findings


def _parse_property(line: str) -> tuple[str, str] | None:
    """Parse only one direct non-continuation Java-properties assignment."""
    if line.endswith("\\"):
        return None
    separator_indexes = [index for index in (line.find("="), line.find(":")) if index >= 0]
    if not separator_indexes:
        return None
    separator = min(separator_indexes)
    key = line[:separator].strip()
    value = line[separator + 1 :].strip()
    return key, value
