"""AST-based detection of selected Python raw SQL construction patterns."""

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


class SqlInjectionControl:
    """Detect direct and bounded local-flow SQL interpolation passed to execute calls."""

    control_id = "SEC-SAST-001"
    control_version = "0.2.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = [path for path in context.inventory.files if path.suffix == ".py"]
        if not python_files:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No Python source files were in the bounded inventory.",
                )
            )

        findings: list[Finding] = []
        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not _is_execute_call(node) or not node.args:
                    continue
                construction = _unsafe_sql_construction(node.args[0])
                if construction is not None:
                    findings.append(_sql_interpolation_finding(self, relative, node, construction))
            for node, construction in _unsafe_local_assignment_sinks(tree):
                findings.append(
                    _sql_interpolation_finding(
                        self,
                        relative,
                        node,
                        construction,
                        flow="local_straight_line_assignment",
                    )
                )

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Parsed {len(python_files)} Python source files.",
            ),
            findings=tuple(findings),
        )


class SqlInjectionSingleLocalAliasControl:
    """Detect one local unsafe-SQL-name to alias-name flow into a standalone execute sink.

    This control intentionally follows exactly one direct ``name = source_name`` alias in the same
    lexical scope. It does not perform general dataflow or follow branches, calls, imports,
    attributes, closures, reassignments hidden in compound statements, or alias chains.
    """

    control_id = "SEC-SAST-SQL-ALIAS-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = [path for path in context.inventory.files if path.suffix == ".py"]
        if not python_files:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No Python source files were in the bounded inventory.",
                )
            )

        findings: list[Finding] = []
        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error
            for node, construction in _unsafe_single_local_alias_sinks(tree):
                findings.append(
                    _sql_interpolation_finding(
                        self,
                        relative,
                        node,
                        construction,
                        flow="single_local_name_alias",
                    )
                )

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    f"Parsed {len(python_files)} Python source files for one local unsafe-SQL alias "
                    "flow."
                ),
            ),
            findings=tuple(findings),
        )


def _sql_interpolation_finding(
    control: SqlInjectionControl | SqlInjectionSingleLocalAliasControl,
    relative_path: str,
    node: ast.Call,
    construction: str,
    *,
    flow: str | None = None,
) -> Finding:
    location = Location(path=relative_path, start_line=node.lineno)
    evidence = {"construction": construction, "sink": _call_name(node.func)}
    if flow is not None:
        evidence["flow"] = flow
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title="Potential SQL injection through string interpolation",
        message=(
            "A SQL execute call receives a query built through string interpolation instead "
            "of a parameterized statement."
        ),
        remediation=(
            "Use the database driver's parameter binding or ORM query parameters; do not "
            "interpolate user-controlled values into SQL text."
        ),
        severity=Severity.BLOCKER,
        confidence=Confidence.HIGH,
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _unsafe_single_local_alias_sinks(tree: ast.Module) -> tuple[tuple[ast.Call, str], ...]:
    """Find only one simple same-scope name alias from unsafe SQL to a standalone sink."""
    sinks: list[tuple[ast.Call, str]] = []
    _scan_single_alias_scope(tree.body, sinks)
    return tuple(sinks)


def _scan_single_alias_scope(
    statements: list[ast.stmt], sinks: list[tuple[ast.Call, str]]
) -> None:
    unsafe_sources: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_single_alias_scope(statement.body, sinks)
            continue
        if isinstance(statement, ast.ClassDef):
            for member in statement.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _scan_single_alias_scope(member.body, sinks)
            continue
        if isinstance(statement, ast.Assign):
            _track_single_alias_assignment(statement, unsafe_sources, aliases)
            continue
        if isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
            _invalidate_single_alias_target(statement.target, unsafe_sources, aliases)
            continue
        call = _standalone_execute_call(statement)
        if call is not None and call.args and isinstance(call.args[0], ast.Name):
            construction = aliases.get(call.args[0].id)
            if construction is not None:
                sinks.append((call, construction))
            continue
        _invalidate_nested_single_alias_names(statement, unsafe_sources, aliases)


def _track_single_alias_assignment(
    statement: ast.Assign, unsafe_sources: dict[str, str], aliases: dict[str, str]
) -> None:
    if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
        for target in statement.targets:
            _invalidate_single_alias_target(target, unsafe_sources, aliases)
        return
    target = statement.targets[0].id
    construction = _unsafe_sql_construction(statement.value)
    if construction is not None:
        unsafe_sources[target] = construction
        aliases.pop(target, None)
        return
    if isinstance(statement.value, ast.Name) and statement.value.id in unsafe_sources:
        aliases[target] = unsafe_sources[statement.value.id]
        unsafe_sources.pop(target, None)
        return
    unsafe_sources.pop(target, None)
    aliases.pop(target, None)


def _invalidate_single_alias_target(
    target: ast.expr, unsafe_sources: dict[str, str], aliases: dict[str, str]
) -> None:
    if isinstance(target, ast.Name):
        unsafe_sources.pop(target.id, None)
        aliases.pop(target.id, None)


def _invalidate_nested_single_alias_names(
    statement: ast.stmt, unsafe_sources: dict[str, str], aliases: dict[str, str]
) -> None:
    for node in ast.walk(statement):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            unsafe_sources.pop(node.id, None)
            aliases.pop(node.id, None)


def _unsafe_local_assignment_sinks(tree: ast.Module) -> tuple[tuple[ast.Call, str], ...]:
    """Find only straight-line local name assignments in one lexical scope.

    This is intentionally not dataflow analysis. It does not follow imports, calls, attributes,
    assignments in branches/loops/with/try blocks, closures, globals, aliases, or redefinitions
    hidden in nested statements.
    """
    sinks: list[tuple[ast.Call, str]] = []
    _scan_local_scope(tree.body, sinks)
    return tuple(sinks)


def _scan_local_scope(
    statements: list[ast.stmt], sinks: list[tuple[ast.Call, str]]
) -> None:
    unsafe_assignments: dict[str, str] = {}
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_local_scope(statement.body, sinks)
            continue
        if isinstance(statement, ast.ClassDef):
            for member in statement.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _scan_local_scope(member.body, sinks)
            continue
        if isinstance(statement, ast.Assign):
            _track_assignment(statement.targets, statement.value, unsafe_assignments)
            continue
        if isinstance(statement, ast.AnnAssign):
            _track_assignment((statement.target,), statement.value, unsafe_assignments)
            continue
        if isinstance(statement, ast.AugAssign):
            _invalidate_assignment_names((statement.target,), unsafe_assignments)
            continue
        call = _standalone_execute_call(statement)
        if call is not None and call.args and isinstance(call.args[0], ast.Name):
            construction = unsafe_assignments.get(call.args[0].id)
            if construction is not None:
                sinks.append((call, construction))
            continue
        _invalidate_nested_assignment_names(statement, unsafe_assignments)


def _track_assignment(
    targets: list[ast.expr] | tuple[ast.expr, ...],
    value: ast.expr | None,
    unsafe_assignments: dict[str, str],
) -> None:
    construction = _unsafe_sql_construction(value) if value is not None else None
    for target in targets:
        if not isinstance(target, ast.Name):
            continue
        if construction is None:
            unsafe_assignments.pop(target.id, None)
        else:
            unsafe_assignments[target.id] = construction


def _invalidate_assignment_names(
    targets: list[ast.expr] | tuple[ast.expr, ...], unsafe_assignments: dict[str, str]
) -> None:
    for target in targets:
        if isinstance(target, ast.Name):
            unsafe_assignments.pop(target.id, None)


def _standalone_execute_call(statement: ast.stmt) -> ast.Call | None:
    if not isinstance(statement, ast.Expr):
        return None
    value = statement.value
    if isinstance(value, ast.Await):
        value = value.value
    if isinstance(value, ast.Call) and _is_execute_call(value):
        return value
    return None


def _invalidate_nested_assignment_names(statement: ast.stmt, unsafe_assignments: dict[str, str]) -> None:
    """Forget tracked values when a skipped compound statement may redefine them."""
    for node in ast.walk(statement):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            unsafe_assignments.pop(node.id, None)


def _is_execute_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}


def _unsafe_sql_construction(node: ast.AST) -> str | None:
    if isinstance(node, ast.JoinedStr):
        return "f_string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_string_literal(node.left):
        return "percent_format"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_string_literal(node.func.value)
    ):
        return "format_method"
    return None


def _is_string_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return "call"
