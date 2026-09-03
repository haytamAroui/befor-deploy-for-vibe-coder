"""Bounded FastAPI SSRF analysis for one local alias from a direct route parameter."""
from __future__ import annotations

import ast

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.controls.fastapi_ssrf import (
    _direct_string_parameters,
    _has_literal_fastapi_route,
    _imported_client_modules,
    _imports_fastapi,
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

_CONTROL_ID = "SEC-FASTAPI-SSRF-ALIAS-001"
_CONTROL_VERSION = "0.1.0"
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class FastApiSingleAliasSsrfControl:
    """Flag exactly one local alias from a direct FastAPI string parameter to an HTTP sink."""

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        supported_routes_seen = False
        findings: list[Finding] = []

        for path in context.inventory.files:
            if path.suffix != ".py":
                continue
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error

            imported_clients = _imported_client_modules(tree)
            if not imported_clients or not _imports_fastapi(tree):
                continue

            for function in ast.walk(tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not _has_literal_fastapi_route(function):
                    continue
                supported_routes_seen = True
                parameters = _direct_string_parameters(function)
                if not parameters:
                    continue

                aliases = _single_local_aliases(function, parameters)
                if not aliases:
                    continue

                for call in ast.walk(function):
                    alias = _http_sink_alias(call, aliases, imported_clients)
                    if alias is None:
                        continue
                    location = Location(path=relative, start_line=call.lineno)
                    evidence = {
                        "artifact": "python",
                        "flow": "fastapi_parameter_single_local_alias_to_http_client",
                        "sink_family": "requests_or_httpx_module_call",
                    }
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="FastAPI URL parameter reaches an outbound HTTP client through one local alias",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            message="A direct route parameter is copied once to a local name and then reaches a supported outbound HTTP sink.",
                            remediation="Resolve outbound destinations through an explicit allowlist and validate scheme, host, resolved address, redirects, and destination policy before fetching.",
                            location=location,
                            evidence=evidence,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                        )
                    )

        if not supported_routes_seen:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No supported literal FastAPI route using an imported requests/httpx module was detected.",
                )
            )

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
            ),
            findings=tuple(findings),
        )


def _single_local_aliases(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parameters: frozenset[str],
) -> frozenset[str]:
    aliases: set[str] = set()
    for statement in function.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if isinstance(statement.value, ast.Name) and statement.value.id in parameters:
            aliases.add(target.id)
    return frozenset(aliases)


def _http_sink_alias(
    node: ast.AST,
    aliases: frozenset[str],
    imported_clients: frozenset[str],
) -> str | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if not isinstance(node.func.value, ast.Name) or node.func.value.id not in imported_clients:
        return None

    method = node.func.attr
    url_argument: ast.expr | None = None
    if method in _HTTP_METHODS and node.args:
        url_argument = node.args[0]
    elif method == "request" and len(node.args) >= 2:
        url_argument = node.args[1]
    else:
        for keyword in node.keywords:
            if keyword.arg == "url" and method in _HTTP_METHODS | {"request"}:
                url_argument = keyword.value
                break

    if isinstance(url_argument, ast.Name) and url_argument.id in aliases:
        return url_argument.id
    return None
