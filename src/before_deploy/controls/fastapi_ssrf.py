"""Bounded FastAPI SSRF analysis for direct route parameters passed to HTTP client sinks."""
from __future__ import annotations

import ast

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

_CONTROL_ID = "SEC-FASTAPI-SSRF-001"
_CONTROL_VERSION = "0.1.0"
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete"}
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_CLIENT_MODULES = {"requests", "httpx"}


class FastApiDirectUrlSsrfControl:
    """Flag a direct FastAPI ``str`` parameter passed unchanged to requests/httpx.

    This contract intentionally does not follow aliases, object attributes, helper calls,
    client instances, model fields, concatenation, branches, or interprocedural flow.
    """

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
                user_parameters = _direct_string_parameters(function)
                if not user_parameters:
                    continue

                for call in ast.walk(function):
                    parameter_name = _direct_http_sink_parameter(
                        call,
                        user_parameters=user_parameters,
                        imported_clients=imported_clients,
                    )
                    if parameter_name is None:
                        continue
                    location = Location(path=relative, start_line=call.lineno)
                    evidence = {
                        "artifact": "python",
                        "flow": "fastapi_direct_parameter_to_http_client",
                        "sink_family": "requests_or_httpx_module_call",
                    }
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="FastAPI URL parameter is passed directly to an outbound HTTP client",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            message=(
                                "A direct string route parameter reaches a supported outbound HTTP sink "
                                "without an intervening bounded validation step."
                            ),
                            remediation=(
                                "Resolve outbound destinations through an explicit allowlist and validate "
                                "scheme, host, resolved address, redirects, and destination policy before fetching."
                            ),
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
                    message=(
                        "No supported literal FastAPI route using an imported requests/httpx module "
                        "was detected."
                    ),
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


def _imports_fastapi(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(alias.name == "fastapi" for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "fastapi":
            return True
    return False


def _imported_client_modules(tree: ast.Module) -> frozenset[str]:
    imported: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name in _CLIENT_MODULES and alias.asname is None:
                imported.add(alias.name)
    return frozenset(imported)


def _has_literal_fastapi_route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr not in _ROUTE_METHODS or not decorator.args:
            continue
        path = decorator.args[0]
        if isinstance(path, ast.Constant) and isinstance(path.value, str) and path.value.startswith("/"):
            return True
    return False


def _direct_string_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    parameters: set[str] = set()
    positional = (*function.args.posonlyargs, *function.args.args)
    defaults = (None,) * (len(positional) - len(function.args.defaults)) + tuple(function.args.defaults)
    for parameter, default in zip(positional, defaults, strict=True):
        if _is_direct_string_parameter(parameter, default):
            parameters.add(parameter.arg)
    for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True):
        if _is_direct_string_parameter(parameter, default):
            parameters.add(parameter.arg)
    return frozenset(parameters)


def _is_direct_string_parameter(parameter: ast.arg, default: ast.expr | None) -> bool:
    if not isinstance(parameter.annotation, ast.Name) or parameter.annotation.id != "str":
        return False
    if isinstance(default, ast.Call):
        name = _call_name(default.func)
        if name in {"Depends", "Security"}:
            return False
    return True


def _direct_http_sink_parameter(
    node: ast.AST,
    *,
    user_parameters: frozenset[str],
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

    if isinstance(url_argument, ast.Name) and url_argument.id in user_parameters:
        return url_argument.id
    return None


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None
