"""Bounded detection of direct stack-trace disclosure in Next.js Route Handlers."""

from __future__ import annotations

import re

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

_CONTROL_ID = "SEC-NEXT-ERROR-STACK-001"
_CONTROL_VERSION = "0.1.0"
_ROUTE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
_HANDLER = re.compile(r"\bexport\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(")
_CATCH = re.compile(r"\bcatch\s*\(\s*(?P<name>[A-Za-z_$][\w$]*)\s*\)\s*\{")


class NextRouteStackTraceResponseControl:
    """Flag one direct catch-variable stack disclosure form in Next.js Route Handlers."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        route_files = sorted(
            path
            for path in context.inventory.files
            if path.suffix.lower() in _ROUTE_SUFFIXES and path.stem == "route"
        )
        if not route_files:
            return _not_applicable(started_at, "No supported Next.js Route Handler files were in scope.")

        findings: list[Finding] = []
        supported_handler_seen = False
        for path in route_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read Next.js Route Handler source: {relative}") from error
            structural = _mask_comments_and_strings(source)
            if not _HANDLER.search(structural):
                continue
            supported_handler_seen = True
            for catch in _CATCH.finditer(structural):
                body_open = catch.end() - 1
                body_close = _balanced_brace_end(structural, body_open)
                if body_close is None:
                    continue
                body = structural[body_open + 1 : body_close]
                name = catch.group("name")
                sink = re.compile(
                    rf"\b(?:NextResponse|Response)\s*\.\s*json\s*\([^)]*\b{re.escape(name)}\s*\.\s*stack\b[^)]*\)",
                    re.DOTALL,
                ).search(body)
                if sink is None:
                    continue
                absolute = body_open + 1 + sink.start()
                location = Location(path=relative, start_line=source.count("\n", 0, absolute) + 1)
                evidence = {
                    "artifact": "nextjs_route_handler",
                    "flow": "catch_variable_stack_to_json_response",
                    "sink": "Response.json",
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Next.js Route Handler returns a caught exception stack trace",
                        message=(
                            "A caught exception's stack property is passed directly inside a JSON response in a Next.js Route Handler."
                        ),
                        remediation=(
                            "Return a stable public error code/message and keep stack traces in server-side observability only."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )

        if not supported_handler_seen:
            return _not_applicable(started_at, "No exported async HTTP Route Handler was detected in supported route files.")
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked Next.js Route Handler catch blocks for direct exception-stack JSON disclosure.",
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


def _balanced_brace_end(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _mask_comments_and_strings(source: str) -> str:
    chars = list(source)
    index = 0
    state = "code"
    quote = ""
    escaped = False
    while index < len(chars):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if char in {'\"', "'", "`"}:
                quote = char
                chars[index] = " "
                escaped = False
                state = "string"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                chars[index] = " "
        elif state == "string":
            if char != "\n":
                chars[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        index += 1
    return "".join(chars)
