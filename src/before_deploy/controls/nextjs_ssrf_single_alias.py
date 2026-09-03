"""Bounded Next.js SSRF analysis for one local alias before fetch()."""
from __future__ import annotations

import re

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.controls.nextjs_ssrf import (
    _SOURCE_SUFFIXES,
    _ROUTE_HANDLER,
    _balanced_block_end,
    _is_nextjs,
    _strip_comments_and_strings,
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

_CONTROL_ID = "SEC-NEXT-SSRF-ALIAS-001"
_CONTROL_VERSION = "0.1.0"
_ROUTE_FILES = {"route.js", "route.jsx", "route.ts", "route.tsx"}


class NextSingleAliasQueryFetchSsrfControl:
    """Flag one local alias from a Route Handler query value into fetch().

    Supported flow only::

        const target = request.nextUrl.searchParams.get(<literal>);
        fetch(target)

    The assignment and sink must be in the same named exported App Router Route
    Handler. Chained aliases, reassignment, transformations, branches, body/form
    parsing, helpers, wrappers, alternative clients, and interprocedural flow are
    intentionally excluded.
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
            if path.suffix not in _SOURCE_SUFFIXES or path.name not in _ROUTE_FILES:
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

                assignment_pattern = re.compile(
                    rf"\b(?:const|let)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*"
                    rf"{re.escape(request_name)}\s*\.\s*nextUrl\s*\.\s*searchParams\s*\.\s*"
                    rf"get\s*\(\s*[^)]*\s*\)\s*;?"
                )
                for assignment in assignment_pattern.finditer(body):
                    alias = assignment.group("alias")
                    suffix = body[assignment.end() :]
                    sink = re.search(rf"\bfetch\s*\(\s*{re.escape(alias)}\s*(?:,|\))", suffix)
                    if sink is None:
                        continue
                    between = suffix[: sink.start()]
                    if _has_alias_reassignment(between, alias):
                        continue
                    if _has_control_flow_between(between):
                        continue

                    absolute = opening + assignment.end() + sink.start()
                    location = Location(path=relative, start_line=source.count("\n", 0, absolute) + 1)
                    evidence = {
                        "artifact": "nextjs_route_handler",
                        "flow": "request_nexturl_searchparam_single_alias_to_fetch",
                        "handler_method": handler.group("method"),
                    }
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="Next.js Route Handler query value reaches fetch through one local alias",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            message=(
                                "A request.nextUrl.searchParams.get(...) value is assigned to one local variable "
                                "and then passed unchanged to server-side fetch() in the same Route Handler."
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
                    break

        if not supported_handlers_seen:
            return _not_applicable(started_at, "No supported Next.js App Router Route Handler was detected.")
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked one-local-alias query values passed to fetch() in Next.js Route Handlers.",
            ),
            findings=tuple(findings),
        )


def _has_alias_reassignment(source: str, alias: str) -> bool:
    return re.search(rf"(?:^|[;{{}}\n])\s*{re.escape(alias)}\s*=", source) is not None


def _has_control_flow_between(source: str) -> bool:
    return re.search(r"\b(?:if|for|while|switch|try|catch)\b", source) is not None


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
