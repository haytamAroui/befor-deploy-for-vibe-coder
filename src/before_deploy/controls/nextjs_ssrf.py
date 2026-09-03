"""Bounded Next.js SSRF analysis for direct Route Handler request query values passed to fetch()."""
from __future__ import annotations

import json
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

_CONTROL_ID = "SEC-NEXT-SSRF-001"
_CONTROL_VERSION = "0.1.0"
_SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
_ROUTE_HANDLER = re.compile(
    r"\bexport\s+async\s+function\s+(?P<method>GET|POST|PUT|PATCH|DELETE)\s*\(\s*"
    r"(?P<request>[A-Za-z_$][\w$]*)[^)]*\)\s*\{",
    re.MULTILINE,
)


class NextDirectQueryFetchSsrfControl:
    """Flag one direct Route Handler query-param-to-fetch form.

    Supported flow only:
    ``fetch(request.nextUrl.searchParams.get(<literal>))`` inside a named exported
    App Router Route Handler. Aliases, ``new URL(request.url)``, body/form parsing,
    transformations, helper calls, client wrappers, branches, and interprocedural flow
    are intentionally excluded.
    """

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        if not _is_nextjs(context):
            return _not_applicable(started_at, "Next.js framework was not detected.")

        findings: list[Finding] = []
        supported_handlers_seen = False
        for path in context.inventory.files:
            if path.suffix not in _SOURCE_SUFFIXES or path.name not in {"route.js", "route.jsx", "route.ts", "route.tsx"}:
                continue
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read Next.js source: {relative}") from error

            sanitized = _strip_comments_and_strings(source)
            for handler in _ROUTE_HANDLER.finditer(sanitized):
                opening = handler.end() - 1
                closing = _balanced_block_end(sanitized, opening)
                if closing is None:
                    continue
                supported_handlers_seen = True
                request_name = handler.group("request")
                body = sanitized[opening : closing + 1]
                sink = re.search(
                    rf"\bfetch\s*\(\s*{re.escape(request_name)}\s*\.\s*nextUrl\s*\.\s*"
                    rf"searchParams\s*\.\s*get\s*\(\s*[^)]*\s*\)\s*\)",
                    body,
                )
                if sink is None:
                    continue

                absolute = opening + sink.start()
                location = Location(path=relative, start_line=source.count("\n", 0, absolute) + 1)
                evidence = {
                    "artifact": "nextjs_route_handler",
                    "flow": "request_nexturl_searchparam_direct_to_fetch",
                    "handler_method": handler.group("method"),
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Next.js Route Handler query value is passed directly to fetch",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        message=(
                            "A direct request.nextUrl.searchParams.get(...) expression reaches server-side "
                            "fetch() in the same Route Handler without an intervening bounded validation step."
                        ),
                        remediation=(
                            "Resolve outbound destinations through an explicit allowlist and validate scheme, "
                            "host, resolved address, redirects, and destination policy before fetching."
                        ),
                        location=location,
                        evidence=evidence,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                    )
                )

        if not supported_handlers_seen:
            return _not_applicable(started_at, "No supported Next.js App Router Route Handler was detected.")
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked direct request.nextUrl.searchParams.get(...) values passed to fetch().",
            ),
            findings=tuple(findings),
        )


def _is_nextjs(context: ControlContext) -> bool:
    for path in context.inventory.files:
        if path.name != "package.json":
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        dependencies = raw.get("dependencies", {})
        dev_dependencies = raw.get("devDependencies", {})
        if isinstance(dependencies, dict) and "next" in dependencies:
            return True
        if isinstance(dev_dependencies, dict) and "next" in dev_dependencies:
            return True
    return False


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


def _strip_comments_and_strings(source: str) -> str:
    chars = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if current in {"'", '"', "`"}:
                quote = current
                chars[index] = " "
                state = "string"
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                chars[index] = " "
        elif state == "string":
            if current == "\\":
                chars[index] = " "
                if index + 1 < len(chars) and chars[index + 1] != "\n":
                    chars[index + 1] = " "
                    index += 2
                    continue
            elif current == quote:
                chars[index] = " "
                state = "code"
            elif current != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def _balanced_block_end(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None
