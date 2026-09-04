"""Bounded FastAPI direct command-injection control."""

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

_CONTROL_ID = "SEC-FASTAPI-COMMAND-INJECTION-001"
_CONTROL_VERSION = "0.1.0"
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_SUBPROCESS_SINKS = {"run", "call", "Popen"}
_AUTH_DEPENDENCIES = {"Depends", "Security"}


class FastApiDirectCommandInjectionControl:
    """Flag direct FastAPI string input passed unchanged to a shell command sink.

    Supported sinks are direct ``os.system(parameter)`` and direct
    ``subprocess.run/call/Popen(parameter, shell=True)`` forms, plus their direct
    no-alias ``from ... import ...`` equivalents. The input must be a bare ``str``
    parameter of a literal FastAPI route handler and must not be a direct Depends or
    Security dependency. Imported command names are rejected for the whole file if
    they are rebound.

    Aliases, f-strings, concatenation, local aliases, transformations, wrappers,
    helpers, interprocedural flow, environment/config values, list-form subprocess
    invocation, shell values other than literal ``True``, framework middleware, and
    runtime reachability are intentionally excluded.
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
                raise ValueError(f"Unable to read FastAPI command source: {relative}") from error
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError:
                continue
            if not _imports_fastapi(tree):
                continue

            imports = _supported_command_imports(tree)
            imports = _drop_rebound_imports(tree, imports)
            if not any(imports.values()):
                continue

            for function in (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                if not _has_literal_fastapi_route(function):
                    continue
                user_parameters = _user_string_parameters(function)
                if not user_parameters:
                    continue
                applicable = True
                for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                    sink = _direct_shell_sink(call, imports, user_parameters)
                    if sink is None:
                        continue
                    parameter, sink_name = sink
                    location = Location(path=relative, start_line=getattr(call, "lineno", 1))
                    evidence = {
                        "artifact": "fastapi_route_handler",
                        "flow": "direct_route_string_parameter_to_shell_sink",
                        "request_parameter": parameter,
                        "sink": sink_name,
                    }
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="FastAPI request parameter is passed directly to a shell command sink",
                            message=(
                                f"Route parameter {parameter!r} is passed unchanged to {sink_name}, "
                                "which invokes a command shell in the supported form."
                            ),
                            remediation=(
                                "Do not pass request-controlled strings to a shell. Prefer a fixed executable "
                                "and an argument list with shell disabled, validate inputs against a strict "
                                "allowlist, and keep authorization separate."
                            ),
                            severity=Severity.BLOCKER,
                            confidence=Confidence.HIGH,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                            location=location,
                            evidence=evidence,
                        )
                    )

        if not applicable:
            return _not_applicable(
                started_at,
                "No supported FastAPI route with a bare string request parameter and supported command import was detected.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked direct FastAPI string parameters for supported direct shell-command sinks.",
            ),
            findings=tuple(findings),
        )


def _imports_fastapi(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("fastapi"):
            return True
        if isinstance(node, ast.Import) and any(alias.name == "fastapi" for alias in node.names):
            return True
    return False


def _supported_command_imports(tree: ast.Module) -> dict[str, bool]:
    supported = {
        "os_module": False,
        "subprocess_module": False,
        "system_direct": False,
        "run_direct": False,
        "call_direct": False,
        "Popen_direct": False,
    }
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    continue
                if alias.name == "os":
                    supported["os_module"] = True
                elif alias.name == "subprocess":
                    supported["subprocess_module"] = True
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            if any(alias.name == "system" and alias.asname is None for alias in node.names):
                supported["system_direct"] = True
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for name in _SUBPROCESS_SINKS:
                if any(alias.name == name and alias.asname is None for alias in node.names):
                    supported[f"{name}_direct"] = True
    return supported


def _drop_rebound_imports(tree: ast.Module, imports: dict[str, bool]) -> dict[str, bool]:
    result = dict(imports)
    bindings = {
        "os_module": "os",
        "subprocess_module": "subprocess",
        "system_direct": "system",
        "run_direct": "run",
        "call_direct": "call",
        "Popen_direct": "Popen",
    }
    for key, name in bindings.items():
        if result[key] and _name_is_rebound(tree, name):
            result[key] = False
    return result


def _name_is_rebound(tree: ast.Module, name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id == name:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parameters = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            if any(parameter.arg == name for parameter in parameters):
                return True
            if node.args.vararg is not None and node.args.vararg.arg == name:
                return True
            if node.args.kwarg is not None and node.args.kwarg.arg == name:
                return True
    return False


def _has_literal_fastapi_route(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr not in _HTTP_METHODS:
            continue
        if not decorator.args:
            continue
        route = decorator.args[0]
        if isinstance(route, ast.Constant) and isinstance(route.value, str) and route.value.startswith("/"):
            return True
    return False


def _user_string_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    result: set[str] = set()
    positional = (*function.args.posonlyargs, *function.args.args)
    positional_defaults: dict[str, ast.expr] = {}
    if function.args.defaults:
        names = positional[-len(function.args.defaults) :]
        positional_defaults = dict(zip((item.arg for item in names), function.args.defaults, strict=True))

    for parameter in positional:
        if not _is_bare_str(parameter.annotation):
            continue
        default = positional_defaults.get(parameter.arg)
        if default is not None and _is_auth_dependency(default):
            continue
        result.add(parameter.arg)

    for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True):
        if not _is_bare_str(parameter.annotation):
            continue
        if default is not None and _is_auth_dependency(default):
            continue
        result.add(parameter.arg)
    return result


def _is_bare_str(annotation: ast.expr | None) -> bool:
    return isinstance(annotation, ast.Name) and annotation.id == "str"


def _is_auth_dependency(default: ast.expr) -> bool:
    if not isinstance(default, ast.Call):
        return False
    if isinstance(default.func, ast.Name):
        return default.func.id in _AUTH_DEPENDENCIES
    return isinstance(default.func, ast.Attribute) and default.func.attr in _AUTH_DEPENDENCIES


def _direct_shell_sink(
    call: ast.Call,
    imports: dict[str, bool],
    user_parameters: set[str],
) -> tuple[str, str] | None:
    if not call.args or not isinstance(call.args[0], ast.Name):
        return None
    parameter = call.args[0].id
    if parameter not in user_parameters:
        return None

    if imports["os_module"] and _module_call(call, "os", "system"):
        return parameter, "os.system"
    if imports["system_direct"] and isinstance(call.func, ast.Name) and call.func.id == "system":
        return parameter, "os.system"

    subprocess_sink = _subprocess_sink_name(call, imports)
    if subprocess_sink is None or not _literal_shell_true(call):
        return None
    return parameter, subprocess_sink


def _module_call(call: ast.Call, module: str, attribute: str) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == attribute
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == module
    )


def _subprocess_sink_name(call: ast.Call, imports: dict[str, bool]) -> str | None:
    for name in _SUBPROCESS_SINKS:
        if imports["subprocess_module"] and _module_call(call, "subprocess", name):
            return f"subprocess.{name}"
        if imports[f"{name}_direct"] and isinstance(call.func, ast.Name) and call.func.id == name:
            return f"subprocess.{name}"
    return None


def _literal_shell_true(call: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
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
