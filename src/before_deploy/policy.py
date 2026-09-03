"""Versioned policy profiles and the deterministic release decision engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from before_deploy.models import (
    ControlExecution,
    CoverageAudit,
    CoverageStatus,
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
class DependencyAuditPolicy:
    """The declared, non-ambiguous dependency evidence source for pip-audit."""

    input_kind: str
    requirements_path: str | None = None


@dataclass(frozen=True)
class ProvenancePolicy:
    """Expected identity and local evidence paths for artifact-attestation verification."""

    artifact_path: str
    bundle_path: str
    repository: str
    signer_workflow: str


@dataclass(frozen=True)
class AssurancePolicy:
    """Policy-owned minimum acceptable coverage for explicitly required domains."""

    minimum_domain_coverage: Mapping[str, CoverageStatus] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyProfile:
    """Validated, reviewable policy data loaded from YAML."""

    schema_version: int
    name: str
    controls: Mapping[str, ControlPolicy]
    public_fastapi_routes: frozenset[tuple[str, str]]
    tools: Mapping[str, ExternalToolPolicy] = field(default_factory=dict)
    dependency_audit: DependencyAuditPolicy | None = None
    provenance: ProvenancePolicy | None = None
    allow_nonrequired_control_errors: bool = False
    assurance: AssurancePolicy = field(default_factory=AssurancePolicy)


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
    dependency_audit = _parse_dependency_audit(raw.get("dependency_audit"))
    provenance = _parse_provenance(raw.get("provenance"))
    assurance = _parse_assurance(raw.get("assurance"))
    allow_errors = raw.get("allow_nonrequired_control_errors", False)
    if not isinstance(allow_errors, bool):
        raise ValueError("allow_nonrequired_control_errors must be boolean")

    return PolicyProfile(
        schema_version=schema_version,
        name=name.strip(),
        controls=controls,
        public_fastapi_routes=routes,
        tools=tools,
        dependency_audit=dependency_audit,
        provenance=provenance,
        allow_nonrequired_control_errors=allow_errors,
        assurance=assurance,
    )


def evaluate(
    *,
    manifest: ScanManifest,
    executions: tuple[ControlExecution, ...],
    findings: tuple[Finding, ...],
    waivers: tuple[Waiver, ...],
    profile: PolicyProfile,
    coverage_audit: CoverageAudit | None = None,
) -> tuple[tuple[Finding, ...], PolicyDecision]:
    """Assign policy dispositions and produce the sole deterministic gate outcome."""
    execution_by_id = {execution.control_id: execution for execution in executions}
    errors: set[str] = set()
    reason_codes: set[str] = set()

    _evaluate_assurance(profile, coverage_audit, errors, reason_codes)

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


_COVERAGE_RANK = {
    CoverageStatus.PARTIAL: 1,
    CoverageStatus.COVERED: 2,
}


def _evaluate_assurance(
    profile: PolicyProfile,
    coverage_audit: CoverageAudit | None,
    errors: set[str],
    reason_codes: set[str],
) -> None:
    """Apply explicit assurance requirements while keeping policy as sole authority."""
    requirements = profile.assurance.minimum_domain_coverage
    if not requirements:
        return

    if coverage_audit is None:
        errors.add("ASSURANCE:COVERAGE_AUDIT_MISSING")
        reason_codes.add("ASSURANCE_COVERAGE_AUDIT_MISSING")
        return

    by_domain_id = {
        assessment.domain_id: assessment
        for assessment in coverage_audit.assessments
        if assessment.domain_id is not None
    }

    for domain_id, minimum_status in sorted(requirements.items()):
        assessment = by_domain_id.get(domain_id)
        if assessment is None:
            errors.add(f"ASSURANCE:{domain_id}")
            reason_codes.add(f"ASSURANCE_DOMAIN_MISSING:{domain_id}")
            continue

        actual_rank = _COVERAGE_RANK.get(assessment.status, 0)
        required_rank = _COVERAGE_RANK[minimum_status]
        if actual_rank < required_rank:
            errors.add(f"ASSURANCE:{domain_id}")
            reason_codes.add(
                f"ASSURANCE_COVERAGE_INSUFFICIENT:{domain_id}:"
                f"{assessment.status.value}:REQUIRES_{minimum_status.value}"
            )
        else:
            reason_codes.add(
                f"ASSURANCE_COVERAGE_SATISFIED:{domain_id}:{assessment.status.value}"
            )


def _parse_assurance(raw_assurance: Any) -> AssurancePolicy:
    if raw_assurance is None:
        return AssurancePolicy()
    if not isinstance(raw_assurance, dict):
        raise ValueError("assurance must be a mapping")

    raw_minimums = raw_assurance.get("minimum_domain_coverage", {})
    if not isinstance(raw_minimums, dict):
        raise ValueError("assurance.minimum_domain_coverage must be a mapping")

    minimums: dict[str, CoverageStatus] = {}
    for domain_id, raw_status in raw_minimums.items():
        if not isinstance(domain_id, str) or not domain_id.startswith("DOMAIN-"):
            raise ValueError(
                "assurance.minimum_domain_coverage keys must be stable DOMAIN-* identifiers"
            )
        try:
            status = CoverageStatus(raw_status)
        except ValueError as error:
            raise ValueError(
                f"assurance minimum for {domain_id} must be PARTIAL or COVERED"
            ) from error
        if status not in _COVERAGE_RANK:
            raise ValueError(
                f"assurance minimum for {domain_id} must be PARTIAL or COVERED"
            )
        minimums[domain_id] = status

    return AssurancePolicy(minimum_domain_coverage=minimums)


def _parse_dependency_audit(raw_dependency_audit: Any) -> DependencyAuditPolicy | None:
    if raw_dependency_audit is None:
        return None
    if not isinstance(raw_dependency_audit, dict):
        raise ValueError("dependency_audit must be a mapping")
    input_kind = raw_dependency_audit.get("input")
    requirements_path = raw_dependency_audit.get("requirements_path")
    if input_kind not in {"uv_lock", "requirements"}:
        raise ValueError("dependency_audit.input must be either 'uv_lock' or 'requirements'")
    if input_kind == "requirements":
        if not isinstance(requirements_path, str) or not requirements_path.strip():
            raise ValueError("dependency_audit.requirements_path is required for requirements input")
        candidate = Path(requirements_path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("dependency_audit.requirements_path must be a repository-relative path")
        return DependencyAuditPolicy(input_kind=input_kind, requirements_path=requirements_path)
    if requirements_path is not None:
        raise ValueError("dependency_audit.requirements_path is only valid for requirements input")
    return DependencyAuditPolicy(input_kind=input_kind)


def _parse_provenance(raw_provenance: Any) -> ProvenancePolicy | None:
    if raw_provenance is None:
        return None
    if not isinstance(raw_provenance, dict):
        raise ValueError("provenance must be a mapping")
    artifact_path = raw_provenance.get("artifact_path")
    bundle_path = raw_provenance.get("bundle_path")
    repository = raw_provenance.get("repository")
    signer_workflow = raw_provenance.get("signer_workflow")
    for field_name, value in (("artifact_path", artifact_path), ("bundle_path", bundle_path)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"provenance.{field_name} must be a non-empty string")
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"provenance.{field_name} must be a repository-relative path")
    if not isinstance(repository, str) or repository.count("/") != 1 or not all(repository.split("/")):
        raise ValueError("provenance.repository must have the owner/repository form")
    if not isinstance(signer_workflow, str) or not signer_workflow.strip():
        raise ValueError("provenance.signer_workflow must be a non-empty string")
    return ProvenancePolicy(
        artifact_path=artifact_path,
        bundle_path=bundle_path,
        repository=repository,
        signer_workflow=signer_workflow,
    )


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
