"""Bounded FastAPI session-cookie hardening control."""

from __future__ import annotations

import ast
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

_CONTROL_ID = "SEC-FASTAPI-SESSION-COOKIE-001"
_CONTROL_VERSION = "0.1.0"
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_SESSION_LIKE = re.compile(r"(?:session|auth|token|jwt)", re.IGNORECASE)


class FastApiUnsafeSessionCookieControl:
    """Flag explicit unsafe flags on a session-like cookie set via a FastAPI Response parameter.

    This rule intentionally accepts only a literal FastAPI route-decorator shape, a bare ``Response``
    parameter annotation, and a direct ``that_parameter.set_cookie(...)`` call. It reports only
    explicitly unsafe ``httponly=False`` or ``secure=False`` keyword arguments. Missing flags,
    aliases, response objects created inside the handler, middleware/session configuration, custom
    wrappers, cookie deletion, runtime TLS termination, and effective browser behavior are excluded.
    """

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = sorted(path for path in context.inventory.files if path.suffix == ".py")
        if not python_files:
            return _not_applicable(started_at, "No Python source files were in scope.")

        findings: list[Finding] = []
        applicable = False
        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read FastAPI source: {relative}") from error
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError:
                continue
            if not _imports_fastapi(tree):
                continue
            for function in (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                if not _has_fastapi_route(function):
                    continue
                response_parameters = _response_parameters(function)
                if not response_parameters:
                    continue
                applicable = True
                for call in (
                    node
                    for node in ast.walk(function)
                    if isinstance(node, ast.Call) and _is_response_set_cookie(node, response_parameters)
                ):
                    cookie_name = _static_cookie_name(call)
                    if cookie_name is None or _SESSION_LIKE.search(cookie_name) is None:
                        continue
                    unsafe = _explicit_unsafe_options(call)
                    if not unsafe:
                        continue
                    location = Location(path=relative, start_line=getattr(call, "lineno", 1))
                    evidence = {
                        "artifact": "fastapi_route_handler",
                        "cookie": cookie_name,
                        "flow": "fastapi_response_parameter_set_cookie",
                        "unsafe_options": ",".join(sorted(unsafe)),
                    }
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="FastAPI session-like cookie explicitly disables a security flag",
                            message=(
                                f"Session-like cookie {cookie_name!r} is set through a FastAPI Response "
                                f"parameter with explicit unsafe option(s): {', '.join(sorted(unsafe))}."
                            ),
                            remediation=(
                                "Set httponly=True and secure=True for session/authentication cookies when "
                                "appropriate for the deployment, and review SameSite, expiry, path, and domain "
                                "settings separately."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                            location=location,
                            evidence=evidence,
                        )
                    )

        if not applicable:
            return _not_applicable(
                started_at,
                "No supported FastAPI route with a bare Response parameter annotation was detected.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    "Checked direct set_cookie calls on FastAPI Response parameters for explicit unsafe "
                    "session-cookie flags."
                ),
            ),
            findings=tuple(findings),
        )


def _imports_fastapi(tree: ast.AST) -> bool:
    for node in getattr(tree, "body", ()):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("fastapi"):
            return True
        if isinstance(node, ast.Import) and any(alias.name == "fastapi" for alias in node.names):
            return True
    return False


def _has_fastapi_route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr in _HTTP_METHODS:
            return True
    return False


def _response_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    parameters = (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
    return {
        parameter.arg
        for parameter in parameters
        if isinstance(parameter.annotation, ast.Name) and parameter.annotation.id == "Response"
    }


def _is_response_set_cookie(call: ast.Call, response_parameters: set[str]) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "set_cookie"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in response_parameters
    )


def _static_cookie_name(call: ast.Call) -> str | None:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    for keyword in call.keywords:
        if keyword.arg == "key" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return None


def _explicit_unsafe_options(call: ast.Call) -> set[str]:
    unsafe: set[str] = set()
    for keyword in call.keywords:
        if keyword.arg not in {"httponly", "secure"}:
            continue
        if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
            unsafe.add(f"{keyword.arg}=False")
    return unsafe


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
