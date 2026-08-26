"""Versioned policy profiles and the deterministic release decision engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from before_deploy.models import (
    ControlExecution,
    Disposition,
    ExecutionStatus,
    Finding,
    GateOutcome,
    PolicyDecision,
    ScanManifest,
    Waiver,
)
from before_deploy.waivers import matches_waiver


@dataclass(frozen=True)
class ControlPolicy:
    """Policy configuration for a single control ID."""

    required: bool
    disposition: Disposition


@dataclass(frozen=True)
class ExternalToolPolicy:
    """Bounded policy settings for a named external scanner."""

    executable: str
    version: str
    timeout_seconds: int
    max_report_bytes: int


@dataclass(frozen=True)
class PolicyProfile:
    """Validated, reviewable policy data loaded from YAML."""

    schema_version: int
    name: str
    controls: Mapping[str, ControlPolicy]
    public_fastapi_routes: frozenset[tuple[str, str]]
    tools: Mapping[str, ExternalToolPolicy] = field(default_factory=dict)
    allow_nonrequired_control_errors: bool = False


def load_policy(path: Path) -> PolicyProfile:
    """Load a narrow YAML policy schema and reject malformed configuration."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"Unable to load policy: {path}") from error
    if not isinstance(raw, dict):
        raise ValueError("Policy root must be a mapping")

    schema_version = raw.get("schema_version")
    name = raw.get("profile")
    raw_controls = raw.get("controls")
    if schema_version != 1:
        raise ValueError("Policy schema_version must be 1")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Policy profile must be a non-empty string")
    if not isinstance(raw_controls, dict) or not raw_controls:
        raise ValueError("Policy controls must be a non-empty mapping")

    controls: dict[str, ControlPolicy] = {}
    for control_id, value in raw_controls.items():
        if not isinstance(control_id, str) or not isinstance(value, dict):
            raise ValueError("Every control must have a string ID and mapping configuration")
        required = value.get("required")
        raw_disposition = value.get("disposition")
        if not isinstance(required, bool):
            raise ValueError(f"Control {control_id} requires a boolean 'required' field")
        try:
            disposition = Disposition(raw_disposition)
        except ValueError as error:
            raise ValueError(f"Control {control_id} has an invalid disposition") from error
        controls[control_id] = ControlPolicy(required=required, disposition=disposition)

    routes = _parse_public_routes(raw.get("public_fastapi_routes", []))
    tools = _parse_external_tools(raw.get("external_tools", {}))
    allow_errors = raw.get("allow_nonrequired_control_errors", False)
    if not isinstance(allow_errors, bool):
        raise ValueError("allow_nonrequired_control_errors must be boolean")

    return PolicyProfile(
        schema_version=schema_version,
        name=name.strip(),
        controls=controls,
        public_fastapi_routes=routes,
        tools=tools,
        allow_nonrequired_control_errors=allow_errors,
    )


def evaluate(
    *,
    manifest: ScanManifest,
    executions: tuple[ControlExecution, ...],
    findings: tuple[Finding, ...],
    waivers: tuple[Waiver, ...],
    profile: PolicyProfile,
) -> tuple[tuple[Finding, ...], PolicyDecision]:
    """Assign policy dispositions and produce the sole deterministic gate outcome."""
    execution_by_id = {execution.control_id: execution for execution in executions}
    errors: set[str] = set()
    reason_codes: set[str] = set()

    for control_id, control_policy in profile.controls.items():
        execution = execution_by_id.get(control_id)
        if control_policy.required and execution is None:
            errors.add(control_id)
            reason_codes.add(f"REQUIRED_CONTROL_MISSING:{control_id}")
            continue
        if execution and execution.status == ExecutionStatus.ERROR:
            if control_policy.required or not profile.allow_nonrequired_control_errors:
                errors.add(control_id)
                reason_codes.add(f"CONTROL_ERROR:{control_id}")

    evaluated_findings: list[Finding] = []
    blocking: set[str] = set()
    waiver_required: set[str] = set()
    waived: set[str] = set()
    advisory: set[str] = set()

    for finding in findings:
        control_policy = profile.controls.get(finding.rule_id)
        if control_policy is None:
            errors.add(f"UNCONFIGURED_RULE:{finding.rule_id}")
            reason_codes.add(f"UNCONFIGURED_FINDING:{finding.rule_id}")
            configured = finding.with_disposition(Disposition.WARN)
        else:
            configured = finding.with_disposition(control_policy.disposition)
        matching_waiver = next(
            (
                waiver
                for waiver in waivers
                if matches_waiver(
                    waiver=waiver,
                    finding=configured,
                    repository_digest=manifest.repository_digest,
                )
            ),
            None,
        )
        evaluated_findings.append(configured)
        if matching_waiver:
            waived.add(configured.fingerprint)
            reason_codes.add(f"WAIVED:{configured.rule_id}")
            continue
        if configured.disposition == Disposition.BLOCK:
            blocking.add(configured.fingerprint)
            reason_codes.add(f"BLOCKING_FINDING:{configured.rule_id}")
        elif configured.disposition == Disposition.WAIVER_REQUIRED:
            waiver_required.add(configured.fingerprint)
            reason_codes.add(f"WAIVER_REQUIRED:{configured.rule_id}")
        else:
            advisory.add(configured.fingerprint)
            reason_codes.add(f"ADVISORY_FINDING:{configured.rule_id}")

    if errors:
        outcome = GateOutcome.ERROR
    elif blocking:
        outcome = GateOutcome.BLOCK
    elif waiver_required:
        outcome = GateOutcome.WAIVER_REQUIRED
    elif _all_not_evaluated(executions):
        outcome = GateOutcome.NOT_EVALUATED
        reason_codes.add("NO_APPLICABLE_CONTROLS")
    else:
        outcome = GateOutcome.PASS
        reason_codes.add("REQUIRED_CONTROLS_SATISFIED")

    decision = PolicyDecision(
        outcome=outcome,
        reason_codes=tuple(sorted(reason_codes)),
        blocking_fingerprints=tuple(sorted(blocking)),
        waiver_required_fingerprints=tuple(sorted(waiver_required)),
        waived_fingerprints=tuple(sorted(waived)),
        advisory_fingerprints=tuple(sorted(advisory)),
        error_control_ids=tuple(sorted(errors)),
    )
    return tuple(evaluated_findings), decision


def _parse_external_tools(raw_tools: Any) -> Mapping[str, ExternalToolPolicy]:
    if raw_tools is None:
        return {}
    if not isinstance(raw_tools, dict):
        raise ValueError("external_tools must be a mapping")
    tools: dict[str, ExternalToolPolicy] = {}
    for name, raw_tool in raw_tools.items():
        if not isinstance(name, str) or not isinstance(raw_tool, dict):
            raise ValueError("Each external tool must have a string name and mapping configuration")
        executable = raw_tool.get("executable")
        version = raw_tool.get("version")
        timeout_seconds = raw_tool.get("timeout_seconds", 60)
        max_report_bytes = raw_tool.get("max_report_bytes", 5_000_000)
        if not isinstance(executable, str) or not executable.strip():
            raise ValueError(f"External tool {name} requires a non-empty executable")
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"External tool {name} requires a non-empty version")
        if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise ValueError(f"External tool {name} timeout_seconds must be a positive integer")
        if not isinstance(max_report_bytes, int) or max_report_bytes <= 0:
            raise ValueError(f"External tool {name} max_report_bytes must be a positive integer")
        tools[name] = ExternalToolPolicy(
            executable=executable,
            version=version,
            timeout_seconds=timeout_seconds,
            max_report_bytes=max_report_bytes,
        )
    return tools


def _parse_public_routes(raw_routes: Any) -> frozenset[tuple[str, str]]:
    if raw_routes is None:
        return frozenset()
    if not isinstance(raw_routes, list):
        raise ValueError("public_fastapi_routes must be a list")
    routes: set[tuple[str, str]] = set()
    for item in raw_routes:
        if not isinstance(item, dict):
            raise ValueError("Every public FastAPI route must be a mapping")
        path = item.get("path")
        methods = item.get("methods")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Public FastAPI route paths must begin with '/'")
        if not isinstance(methods, list) or not methods:
            raise ValueError("Public FastAPI routes require at least one method")
        for method in methods:
            if not isinstance(method, str) or not method:
                raise ValueError("Public FastAPI route methods must be strings")
            routes.add((path, method.upper()))
    return frozenset(routes)


def _all_not_evaluated(executions: tuple[ControlExecution, ...]) -> bool:
    return bool(executions) and all(
        execution.status in {ExecutionStatus.NOT_APPLICABLE, ExecutionStatus.SKIPPED}
        for execution in executions
    )
