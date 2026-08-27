"""Narrow deterministic security controls for visible Next.js source and configuration."""

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

_SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
_SENSITIVE_PUBLIC_NAME = re.compile(
    r"NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE|DATABASE_URL|ACCESS_TOKEN|AUTH_TOKEN|SESSION_TOKEN|API_SECRET)[A-Z0-9_]*",
    re.IGNORECASE,
)
_PUBLIC_ENV_ACCESS = re.compile(r"process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)", re.IGNORECASE)
_COOKIE_SET_START = re.compile(
    r"(?:cookies\(\)|\b[A-Z0-9_$]*?(?:cookie|cookies)[A-Z0-9_$]*)\.set\(",
    re.IGNORECASE,
)
_SESSION_COOKIE_NAME = re.compile(r"(?:session|auth|token|jwt)", re.IGNORECASE)
_EXPLICIT_FALSE = {
    "httpOnly": re.compile(r"\bhttpOnly\s*:\s*false\b", re.IGNORECASE),
    "secure": re.compile(r"\bsecure\s*:\s*false\b", re.IGNORECASE),
}
_SAMESITE_NONE = re.compile(r"\bsameSite\s*:\s*['\"]none['\"]", re.IGNORECASE)
_HEADER_ARRAY_START = re.compile(r"\bheaders\s*:\s*\[")
_CORS_WILDCARD = re.compile(
    r"key\s*:\s*['\"]access-control-allow-origin['\"]\s*,?\s*value\s*:\s*['\"]\*['\"]",
    re.IGNORECASE,
)
_CORS_CREDENTIALS = re.compile(
    r"key\s*:\s*['\"]access-control-allow-credentials['\"]\s*,?\s*value\s*:\s*['\"]true['\"]",
    re.IGNORECASE,
)


class NextPublicEnvironmentControl:
    """Flag obviously secret-like variables intentionally inlined for the browser."""

    control_id = "SEC-NEXT-ENV-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        if not _is_nextjs(context):
            return _not_applicable(self, started_at, "Next.js framework was not detected.")
        findings: list[Finding] = []
        for path in _source_files(context):
            for line_number, line in enumerate(_read_lines(path), start=1):
                if line.lstrip().startswith(("//", "*", "/*")):
                    continue
                for match in _PUBLIC_ENV_ACCESS.finditer(line):
                    variable = match.group(1)
                    if not _SENSITIVE_PUBLIC_NAME.fullmatch(variable):
                        continue
                    location = _location(context, path, line_number)
                    evidence = {"variable": variable, "path": location.path, "line": str(line_number)}
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="Sensitive-looking value exposed through NEXT_PUBLIC_",
                            message=(
                                f"{variable} is directly referenced through NEXT_PUBLIC_, which makes its "
                                "build-time value available to browser JavaScript."
                            ),
                            remediation=(
                                "Remove the NEXT_PUBLIC_ prefix and access the value only from server-side code, "
                                "or replace it with a deliberately public identifier."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                            location=location,
                            evidence=evidence,
                        )
                    )
        return _completed(self, started_at, findings, "Checked direct NEXT_PUBLIC_ environment references.")


class NextSessionCookieControl:
    """Flag explicit insecure options on statically named session-like Next.js cookies."""

    control_id = "SEC-NEXT-COOKIE-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        if not _is_nextjs(context):
            return _not_applicable(self, started_at, "Next.js framework was not detected.")
        findings: list[Finding] = []
        for path in _source_files(context):
            source = _read_source(path)
            for start in (match.start() for match in _COOKIE_SET_START.finditer(source)):
                call = _balanced_call(source, start)
                if call is None:
                    continue
                cookie_name = _static_first_argument(call)
                if cookie_name is None or not _SESSION_COOKIE_NAME.search(cookie_name):
                    continue
                unsafe_options = _unsafe_cookie_options(call)
                if not unsafe_options:
                    continue
                line_number = source.count("\n", 0, start) + 1
                location = _location(context, path, line_number)
                evidence = {
                    "cookie": cookie_name,
                    "unsafe_options": ",".join(sorted(unsafe_options)),
                    "path": location.path,
                    "line": str(line_number),
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Session-like cookie has explicit unsafe options",
                        message=(
                            f"Cookie {cookie_name!r} explicitly sets unsafe options: "
                            f"{', '.join(sorted(unsafe_options))}."
                        ),
                        remediation=(
                            "For session/authentication cookies, use httpOnly: true, secure: true, and an "
                            "appropriate sameSite value; set an explicit expiry/maxAge and path as needed."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )
        return _completed(self, started_at, findings, "Checked explicit options on statically named session cookies.")


class NextStaticCorsControl:
    """Flag static Next.js header arrays that combine wildcard CORS origin and credentials."""

    control_id = "SEC-NEXT-CORS-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        if not _is_nextjs(context):
            return _not_applicable(self, started_at, "Next.js framework was not detected.")
        findings: list[Finding] = []
        for path in _next_config_files(context):
            source = _read_source(path)
            for start in (match.end() - 1 for match in _HEADER_ARRAY_START.finditer(source)):
                array = _balanced_segment(source, start, "[", "]")
                if array is None or not (_CORS_WILDCARD.search(array) and _CORS_CREDENTIALS.search(array)):
                    continue
                line_number = source.count("\n", 0, start) + 1
                location = _location(context, path, line_number)
                evidence = {"path": location.path, "line": str(line_number), "origin": "*", "credentials": "true"}
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Credentialed wildcard CORS is configured in Next.js headers",
                        message=(
                            "A static Next.js headers array combines Access-Control-Allow-Origin '*' with "
                            "Access-Control-Allow-Credentials 'true'."
                        ),
                        remediation=(
                            "Replace the wildcard with an explicit trusted origin, or disable credentialed CORS "
                            "for the affected response scope."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )
        return _completed(self, started_at, findings, "Checked static Next.js CORS header arrays.")


def _is_nextjs(context: ControlContext) -> bool:
    return context.project_profile is not None and "Next.js" in context.project_profile.frameworks


def _source_files(context: ControlContext) -> tuple[Path, ...]:
    return tuple(path for path in context.inventory.files if path.suffix.lower() in _SOURCE_SUFFIXES)


def _next_config_files(context: ControlContext) -> tuple[Path, ...]:
    names = {"next.config.js", "next.config.mjs", "next.config.ts"}
    return tuple(path for path in context.inventory.files if path.name in names)


def _read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_lines(path: Path) -> tuple[str, ...]:
    return tuple(_read_source(path).splitlines())


def _location(context: ControlContext, path: Path, line_number: int) -> Location:
    return Location(path=path.relative_to(context.repository_root).as_posix(), start_line=line_number)


def _not_applicable(control, started_at, message: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=False,
            message=message,
        )
    )


def _completed(control, started_at, findings: list[Finding], message: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.COMPLETED,
            started_at=started_at,
            completed_at=utc_now(),
            message=message,
        ),
        findings=tuple(findings),
    )


def _balanced_call(source: str, start: int) -> str | None:
    open_index = source.find("(", start)
    if open_index < 0:
        return None
    segment = _balanced_segment(source, open_index, "(", ")")
    if segment is None:
        return None
    return source[start:open_index] + segment


def _balanced_segment(source: str, start: int, opening: str, closing: str) -> str | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, min(len(source), start + 4_000)):
        character = source[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
            continue
        if character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    return None


def _static_first_argument(call: str) -> str | None:
    match = re.search(r"\.set\(\s*['\"]([^'\"]+)['\"]", call, re.IGNORECASE)
    return match.group(1) if match else None


def _unsafe_cookie_options(call: str) -> set[str]:
    unsafe = {name for name, pattern in _EXPLICIT_FALSE.items() if pattern.search(call)}
    if _SAMESITE_NONE.search(call) and _EXPLICIT_FALSE["secure"].search(call):
        unsafe.add("sameSite:none with secure:false")
    return unsafe
