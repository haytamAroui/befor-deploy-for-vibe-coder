"""Bounded lexical checks for selected Spring MVC CORS declarations."""

from __future__ import annotations

import re
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

_CROSS_ORIGIN = re.compile(r"^\s*@CrossOrigin\s*\((?P<arguments>[^()]*)\)\s*$")
_WILDCARD_ORIGIN = re.compile(r'\borigins\s*=\s*"\*"')
_CREDENTIALS_TRUE = re.compile(r'\ballowCredentials\s*=\s*"true"')


class SpringCredentialedWildcardCorsControl:
    """Detect one direct single-line credentialed wildcard @CrossOrigin declaration."""

    control_id = "SEC-SPRING-CORS-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        candidates = sorted(path for path in context.inventory.files if path.suffix.lower() == ".java")
        if not candidates:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No Java source files were in scope.",
                )
            )

        findings: list[Finding] = []
        for path in candidates:
            relative = path.relative_to(context.repository_root).as_posix()
            findings.extend(_find_credentialed_wildcard_annotations(self, path, relative))

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Inspected {len(candidates)} Java source file(s) for the bounded annotation form.",
            ),
            findings=tuple(findings),
        )


def _find_credentialed_wildcard_annotations(
    control: SpringCredentialedWildcardCorsControl,
    path: Path,
    relative: str,
) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"Unable to read Java source: {relative}") from error

    findings: list[Finding] = []
    in_block_comment = False
    for line_number, raw_line in enumerate(lines, start=1):
        visible, in_block_comment = _visible_single_line_code(raw_line, in_block_comment)
        if in_block_comment or not visible:
            continue
        match = _CROSS_ORIGIN.fullmatch(visible)
        if match is None:
            continue
        arguments = match.group("arguments")
        if not (_WILDCARD_ORIGIN.search(arguments) and _CREDENTIALS_TRUE.search(arguments)):
            continue

        location = Location(path=relative, start_line=line_number)
        evidence = {
            "artifact": "java_annotation",
            "annotation": "CrossOrigin",
            "origins": "wildcard",
            "allow_credentials": "true",
        }
        findings.append(
            Finding(
                rule_id=control.control_id,
                rule_version=control.control_version,
                title="Spring CrossOrigin combines wildcard origin with credentials",
                message=(
                    "A direct single-line Spring @CrossOrigin declaration explicitly combines a wildcard "
                    "origin with credentialed requests."
                ),
                remediation=(
                    "Replace the wildcard with an explicit trusted-origin allowlist and verify the effective "
                    "CORS policy at the application and proxy boundaries."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint=fingerprint_for(control.control_id, location, evidence),
                location=location,
                evidence=evidence,
            )
        )
    return findings


def _visible_single_line_code(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Remove comments only; quoted annotation arguments remain unchanged."""
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(line):
        char = line[index]
        next_char = line[index + 1] if index + 1 < len(line) else ""

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue

        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            break
        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            continue

        output.append(char)
        index += 1

    return "".join(output).strip(), in_block_comment
