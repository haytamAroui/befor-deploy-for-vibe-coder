"""Deterministic checks for selected production configuration anti-patterns."""

from __future__ import annotations

import ast
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

_CONFIG_SUFFIXES = {".env", ".ini", ".json", ".toml", ".yaml", ".yml"}
_DEBUG_TRUE = re.compile(r"(?im)^\s*[\"']?DEBUG[\"']?\s*[:=]\s*(?:true|1|yes)\b")
_CORS_WILDCARD = re.compile(r"(?is)allow_origins\s*[:=]\s*\[?\s*[\"']\*[\"']")
_CORS_CREDENTIALS = re.compile(r"(?is)allow_credentials\s*[:=]\s*(?:true|1|yes)\b")


class ProductionDebugControl:
    """Detect explicit DEBUG=true declarations in source and config files."""

    control_id = "SEC-CONFIG-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        candidates = _configuration_candidates(context)
        if not candidates:
            return _not_applicable(self, started_at, "No source or configuration files were in scope.")

        findings: list[Finding] = []
        for path in candidates:
            relative = path.relative_to(context.repository_root).as_posix()
            if path.suffix == ".py":
                findings.extend(_debug_findings_from_python(self, path, relative))
            else:
                findings.extend(_debug_findings_from_text(self, path, relative))
        return _completed(self, started_at, findings, f"Inspected {len(candidates)} configuration candidates.")


class CredentialedWildcardCorsControl:
    """Detect explicit CORS wildcard origins combined with credentialed requests."""

    control_id = "SEC-CONFIG-002"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        candidates = _configuration_candidates(context)
        if not candidates:
            return _not_applicable(self, started_at, "No source or configuration files were in scope.")

        findings: list[Finding] = []
        for path in candidates:
            relative = path.relative_to(context.repository_root).as_posix()
            if path.suffix == ".py":
                findings.extend(_cors_findings_from_python(self, path, relative))
            else:
                findings.extend(_cors_findings_from_text(self, path, relative))
        return _completed(self, started_at, findings, f"Inspected {len(candidates)} configuration candidates.")


def _configuration_candidates(context: ControlContext) -> list[Path]:
    return [
        path
        for path in context.inventory.files
        if path.suffix == ".py" or path.suffix.lower() in _CONFIG_SUFFIXES or path.name.startswith(".env")
    ]


def _debug_findings_from_python(
    control: ProductionDebugControl, path: Path, relative: str
) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (OSError, SyntaxError) as error:
        raise ValueError(f"Unable to parse Python source: {relative}") from error
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target_names = _assignment_targets(node)
        value = node.value
        if "DEBUG" not in target_names or not _is_true(value):
            continue
        findings.append(_debug_finding(control, relative, node.lineno, "python_assignment"))
    return findings


def _debug_findings_from_text(
    control: ProductionDebugControl, path: Path, relative: str
) -> list[Finding]:
    text = _read_text(path)
    if text is None:
        return []
    findings: list[Finding] = []
    for match in _DEBUG_TRUE.finditer(text):
        findings.append(_debug_finding(control, relative, _line_for(text, match.start()), "text_config"))
    return findings


def _cors_findings_from_python(
    control: CredentialedWildcardCorsControl, path: Path, relative: str
) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (OSError, SyntaxError) as error:
        raise ValueError(f"Unable to parse Python source: {relative}") from error
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        if _is_wildcard_origins(keywords.get("allow_origins")) and _is_true(
            keywords.get("allow_credentials")
        ):
            findings.append(_cors_finding(control, relative, node.lineno, "python_call"))
    return findings


def _cors_findings_from_text(
    control: CredentialedWildcardCorsControl, path: Path, relative: str
) -> list[Finding]:
    text = _read_text(path)
    if text is None or not (_CORS_WILDCARD.search(text) and _CORS_CREDENTIALS.search(text)):
        return []
    first_match = _CORS_WILDCARD.search(text)
    assert first_match is not None
    return [_cors_finding(control, relative, _line_for(text, first_match.start()), "text_config")]


def _debug_finding(
    control: ProductionDebugControl, relative: str, line: int, source: str
) -> Finding:
    location = Location(path=relative, start_line=line)
    evidence = {"source": source, "setting": "DEBUG=true"}
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title="Debug mode enabled in production-oriented configuration",
        message="A DEBUG setting is explicitly enabled in repository configuration or source.",
        remediation=(
            "Disable debug behavior in deployment configuration and confirm that production error responses "
            "do not expose stack traces or internal settings."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _cors_finding(
    control: CredentialedWildcardCorsControl, relative: str, line: int, source: str
) -> Finding:
    location = Location(path=relative, start_line=line)
    evidence = {"source": source, "allow_origins": "*", "allow_credentials": "true"}
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title="Credentialed CORS allows wildcard origins",
        message="CORS configuration combines a wildcard origin with credentialed requests.",
        remediation=(
            "Use an explicit allowlist of trusted origins when credentials are enabled, and validate the "
            "effective deployment configuration."
        ),
        severity=Severity.BLOCKER,
        confidence=Confidence.HIGH,
        fingerprint=fingerprint_for(control.control_id, location, evidence),
        location=location,
        evidence=evidence,
    )


def _completed(control: object, started_at, findings: list[Finding], message: str) -> ControlResult:
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


def _not_applicable(control: object, started_at, message: str) -> ControlResult:
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


def _assignment_targets(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return {target.id for target in targets if isinstance(target, ast.Name)}


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_wildcard_origins(node: ast.AST | None) -> bool:
    return (
        isinstance(node, (ast.List, ast.Tuple, ast.Set))
        and any(isinstance(item, ast.Constant) and item.value == "*" for item in node.elts)
    )


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    return raw.decode("utf-8", errors="replace")
