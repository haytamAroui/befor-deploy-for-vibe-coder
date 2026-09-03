"""Bounded Spring Security detection for a direct global permit-all request rule."""

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

_CONTROL_ID = "SEC-SPRING-SECURITY-PERMIT-ALL-001"
_CONTROL_VERSION = "0.1.0"
_SECURITY_FILTER_CHAIN_IMPORT = re.compile(
    r"\bimport\s+org\.springframework\.security\.web\.SecurityFilterChain\s*;"
)
_HTTP_SECURITY_IMPORT = re.compile(
    r"\bimport\s+org\.springframework\.security\.config\.annotation\.web\.builders\.HttpSecurity\s*;"
)
_ANY_REQUEST_PERMIT_ALL = re.compile(
    r"\.\s*anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)",
    re.MULTILINE,
)


class SpringAnyRequestPermitAllControl:
    """Flag direct ``anyRequest().permitAll()`` in a Spring Security Java configuration.

    This is intentionally lexical and narrow. A finding requires Java source importing both
    ``SecurityFilterChain`` and ``HttpSecurity`` plus the exact fluent call shape after comments
    and literals are masked. Multiple chains, matcher ordering, custom filters, method security,
    annotations, proxies, runtime bean ordering, and effective deployed authorization remain
    outside the contract.
    """

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        java_files: list[Path] = sorted(
            path for path in context.inventory.files if path.suffix.lower() == ".java"
        )
        if not java_files:
            return _not_applicable(started_at, "No Java source files were in scope.")

        supported_config_seen = False
        findings: list[Finding] = []
        for path in java_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read Java source: {relative}") from error

            visible = _mask_comments_and_literals(source)
            if not (
                _SECURITY_FILTER_CHAIN_IMPORT.search(visible)
                and _HTTP_SECURITY_IMPORT.search(visible)
            ):
                continue
            supported_config_seen = True

            for match in _ANY_REQUEST_PERMIT_ALL.finditer(visible):
                location = Location(
                    path=relative,
                    start_line=source.count("\n", 0, match.start()) + 1,
                )
                evidence = {
                    "artifact": "spring_security_java_config",
                    "request_scope": "any_request",
                    "authorization_rule": "permit_all",
                    "syntax": "anyRequest_permitAll",
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Spring Security permits every request in a supported security chain",
                        message=(
                            "A Spring Security Java configuration contains the direct fluent rule "
                            "anyRequest().permitAll(), which leaves the remaining request space public "
                            "for that configured chain."
                        ),
                        remediation=(
                            "Replace the global permit-all rule with the intended authenticated or "
                            "authorized default, and keep any public endpoints narrowly matched."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )

        if not supported_config_seen:
            return _not_applicable(
                started_at,
                "No Java source with direct Spring SecurityFilterChain and HttpSecurity imports was detected.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked supported Spring Security Java configuration for anyRequest().permitAll().",
            ),
            findings=tuple(findings),
        )


def _not_applicable(started_at, message: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=_CONTROL_ID,
            control_version=_CONTROL_VERSION,
            status=ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=False,
            message=message,
        )
    )


def _mask_comments_and_literals(source: str) -> str:
    chars = list(source)
    index = 0
    state = "code"
    quote = ""
    escaped = False
    while index < len(chars):
        char = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        next_three = source[index : index + 3]
        if state == "code":
            if char == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if char == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if next_three == '"""':
                chars[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "text_block"
                continue
            if char in {'"', "'"}:
                quote = char
                escaped = False
                chars[index] = " "
                state = "literal"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                chars[index] = " "
        elif state == "literal":
            if char != "\n":
                chars[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif state == "text_block":
            if next_three == '"""':
                chars[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "code"
                continue
            if char != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)
