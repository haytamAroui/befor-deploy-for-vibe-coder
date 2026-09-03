"""Bounded lexical detection of direct Spring MVC request input in JPA native queries."""

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

_CONTROL_ID = "SEC-SPRING-JPA-NATIVE-QUERY-001"
_CONTROL_VERSION = "0.1.0"
_MAPPING = re.compile(r"@(?P<annotation>GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\b")
_REQUEST_STRING_PARAMETER = re.compile(
    r"@(?P<source>RequestParam|PathVariable)\b(?:\s*\([^)]*\))?\s+"
    r"(?:(?:final\s+)|(?:@[A-Za-z_$][\w$]*(?:\s*\([^)]*\))?\s+))*"
    r"(?:java\.lang\.)?String\s+(?P<name>[A-Za-z_$][\w$]*)\b",
    re.MULTILINE,
)
_NATIVE_QUERY = re.compile(r"\bcreateNativeQuery\s*\(")
_SPRING_WEB_IMPORT = re.compile(r"\bimport\s+org\.springframework\.web\.bind\.annotation\.(?:\*|[A-Za-z_$][\w$]*)\s*;")
_ENTITY_MANAGER_IMPORT = re.compile(r"\bimport\s+(?:jakarta|javax)\.persistence\.(?:\*|EntityManager)\s*;")
_STRING_LITERAL = r'"(?:\\.|[^"\\])*"'


class SpringRequestParamNativeQueryInjectionControl:
    """Flag one direct Spring request-string-to-native-query concatenation form.

    The accepted flow is intentionally narrow: a mapped Spring MVC method declares a direct
    ``@RequestParam`` or ``@PathVariable`` ``String`` parameter and that exact local parameter is
    concatenated directly with a Java string literal inside the first argument to
    ``EntityManager.createNativeQuery(...)`` in the same method body.

    Aliases, fields, request bodies, DTOs, transformations, helper methods, repository annotations,
    Hibernate Session APIs, JPQL ``createQuery``, Criteria APIs, interprocedural flow, and semantic
    query analysis are outside this contract.
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

        findings: list[Finding] = []
        supported_source_seen = False
        supported_handler_seen = False

        for path in java_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read Java source: {relative}") from error

            comments_removed = _mask_comments(source, preserve_literals=True)
            if not (
                _SPRING_WEB_IMPORT.search(comments_removed)
                and _ENTITY_MANAGER_IMPORT.search(comments_removed)
            ):
                continue
            supported_source_seen = True

            structural = _mask_comments_and_literals(source)
            for mapping in _MAPPING.finditer(structural):
                annotation_end = _annotation_end(structural, mapping.end())
                body_open = _next_top_level_body_open(structural, annotation_end)
                if body_open is None:
                    continue
                header = structural[annotation_end:body_open]
                parameter_span = _last_top_level_parenthesis_span(header)
                if parameter_span is None:
                    continue
                params_start, params_end = parameter_span
                original_header = comments_removed[annotation_end:body_open]
                parameter_text = original_header[params_start + 1 : params_end]
                request_parameters = tuple(_REQUEST_STRING_PARAMETER.finditer(parameter_text))
                if not request_parameters:
                    continue

                body_close = _balanced_delimiter_end(structural, body_open, "{", "}")
                if body_close is None:
                    continue
                supported_handler_seen = True
                body_structural = structural[body_open : body_close + 1]
                body_visible = comments_removed[body_open : body_close + 1]

                for sink in _NATIVE_QUERY.finditer(body_structural):
                    call_open = sink.end() - 1
                    call_close = _balanced_delimiter_end(body_structural, call_open, "(", ")")
                    if call_close is None:
                        continue
                    first_argument = _first_top_level_argument(
                        body_visible[call_open + 1 : call_close]
                    )
                    if first_argument is None:
                        continue

                    for parameter in request_parameters:
                        parameter_name = parameter.group("name")
                        if not _has_direct_literal_concatenation(first_argument, parameter_name):
                            continue
                        absolute = body_open + sink.start()
                        location = Location(
                            path=relative,
                            start_line=source.count("\n", 0, absolute) + 1,
                        )
                        evidence = {
                            "artifact": "spring_mvc_handler",
                            "mapping_annotation": mapping.group("annotation"),
                            "request_source": parameter.group("source"),
                            "request_parameter": parameter_name,
                            "sink": "createNativeQuery",
                            "flow": "direct_request_string_parameter_concat",
                        }
                        findings.append(
                            Finding(
                                rule_id=self.control_id,
                                rule_version=self.control_version,
                                title="Spring request parameter is concatenated into a JPA native query",
                                message=(
                                    "A direct Spring MVC request String parameter is concatenated with SQL "
                                    "text inside EntityManager.createNativeQuery(...) in the same handler."
                                ),
                                remediation=(
                                    "Keep SQL text static and bind request-derived values through JPA query "
                                    "parameters. Validate request values independently of SQL construction."
                                ),
                                severity=Severity.BLOCKER,
                                confidence=Confidence.HIGH,
                                fingerprint=fingerprint_for(self.control_id, location, evidence),
                                location=location,
                                evidence=evidence,
                            )
                        )

        if not supported_source_seen:
            return _not_applicable(
                started_at,
                "No Java source with supported Spring MVC and JPA EntityManager imports was detected.",
            )
        if not supported_handler_seen:
            return _not_applicable(
                started_at,
                "No mapped Spring MVC handler with a direct String request parameter was detected.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    "Checked mapped Spring MVC handlers for direct RequestParam/PathVariable String "
                    "concatenation into JPA createNativeQuery(...)."
                ),
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


def _annotation_end(source: str, position: int) -> int:
    index = position
    while index < len(source) and source[index].isspace():
        index += 1
    if index >= len(source) or source[index] != "(":
        return index
    closing = _balanced_delimiter_end(source, index, "(", ")")
    return len(source) if closing is None else closing + 1


def _next_top_level_body_open(source: str, start: int) -> int | None:
    paren_depth = 0
    bracket_depth = 0
    for index in range(start, min(len(source), start + 2500)):
        char = source[index]
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == ";" and paren_depth == 0 and bracket_depth == 0:
            return None
        elif char == "{" and paren_depth == 0 and bracket_depth == 0:
            return index
    return None


def _last_top_level_parenthesis_span(header: str) -> tuple[int, int] | None:
    spans: list[tuple[int, int]] = []
    depth = 0
    opening = -1
    for index, char in enumerate(header):
        if char == "(":
            if depth == 0:
                opening = index
            depth += 1
        elif char == ")" and depth:
            depth -= 1
            if depth == 0 and opening >= 0:
                spans.append((opening, index))
    return spans[-1] if spans else None


def _balanced_delimiter_end(source: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    state = "code"
    quote = ""
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_three = source[index : index + 3]
        if state == "code":
            if next_three == '"""':
                state = "text_block"
                index += 3
                continue
            if char in {'"', "'"}:
                state = "literal"
                quote = char
                escaped = False
                index += 1
                continue
            if char == left:
                depth += 1
            elif char == right:
                depth -= 1
                if depth == 0:
                    return index
        elif state == "literal":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif state == "text_block":
            if next_three == '"""':
                state = "code"
                index += 3
                continue
        index += 1
    return None


def _first_top_level_argument(arguments: str) -> str | None:
    depth = 0
    state = "code"
    quote = ""
    escaped = False
    index = 0
    while index < len(arguments):
        char = arguments[index]
        next_three = arguments[index : index + 3]
        if state == "code":
            if next_three == '"""':
                state = "text_block"
                index += 3
                continue
            if char in {'"', "'"}:
                state = "literal"
                quote = char
                escaped = False
            elif char in "([{":
                depth += 1
            elif char in ")]}" and depth:
                depth -= 1
            elif char == "," and depth == 0:
                return arguments[:index].strip() or None
        elif state == "literal":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif state == "text_block":
            if next_three == '"""':
                state = "code"
                index += 3
                continue
        index += 1
    return arguments.strip() or None


def _has_direct_literal_concatenation(argument: str, parameter_name: str) -> bool:
    variable = rf"(?<![\w$.]){re.escape(parameter_name)}(?![\w$])"
    literal_then_variable = re.compile(
        rf"{_STRING_LITERAL}\s*\+\s*{variable}(?!\s*[.(])",
        re.DOTALL,
    )
    variable_then_literal = re.compile(
        rf"{variable}\s*\+\s*{_STRING_LITERAL}",
        re.DOTALL,
    )
    return bool(literal_then_variable.search(argument) or variable_then_literal.search(argument))


def _mask_comments(source: str, *, preserve_literals: bool) -> str:
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
                if not preserve_literals:
                    chars[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "text_block"
                continue
            if char in {'"', "'"}:
                quote = char
                escaped = False
                if not preserve_literals:
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
            if not preserve_literals and char != "\n":
                chars[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif state == "text_block":
            if next_three == '"""':
                if not preserve_literals:
                    chars[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "code"
                continue
            if not preserve_literals and char != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def _mask_comments_and_literals(source: str) -> str:
    return _mask_comments(source, preserve_literals=False)
