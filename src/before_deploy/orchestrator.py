"""Deterministic orchestration of inventory, controls, waivers, and policy."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Iterable

from before_deploy.controls.base import Control, ControlContext
from before_deploy.coverage import audit_security_coverage
from before_deploy.evidence import collect_repository_evidence, collect_requirements_evidence
from before_deploy.inventory import collect_inventory, create_manifest
from before_deploy.models import (
    ControlExecution,
    ExecutionStatus,
    ScanResult,
    utc_now,
)
from before_deploy.planning import build_security_analysis_plan
from before_deploy.policy import PolicyProfile, evaluate, load_policy
from before_deploy.project_profile import detect_project_profile, select_compatible_controls
from before_deploy.waivers import load_waivers


class ScanOrchestrator:
    """Runs deterministic controls without allowing one adapter failure to disappear."""

    def __init__(self, controls: Iterable[Control]) -> None:
        self._controls = tuple(controls)

    def scan(
        self,
        repository_path: Path,
        policy_path: Path,
        *,
        waiver_path: Path | None = None,
        max_file_bytes: int = 1_000_000,
    ) -> ScanResult:
        """Scan a bounded repository scope and return the complete decision record."""
        profile = load_policy(policy_path)
        inventory = collect_inventory(repository_path, max_file_bytes=max_file_bytes)
        manifest = create_manifest(
            inventory,
            policy_path=policy_path,
            policy_name=profile.name,
        )
        project_profile = detect_project_profile(inventory)
        runnable_controls, non_applicable_executions = select_compatible_controls(
            self._controls, project_profile
        )
        evidence = (*collect_repository_evidence(inventory, project_profile), *collect_requirements_evidence(inventory))
        security_analysis_plan = build_security_analysis_plan(
            project_profile, evidence, runnable_controls
        )
        waivers = load_waivers(waiver_path)
        context = ControlContext(
            repository_root=inventory.root,
            inventory=inventory,
            project_profile=project_profile,
            public_fastapi_routes=profile.public_fastapi_routes,
        )

        executions: list[ControlExecution] = list(non_applicable_executions)
        findings = []
        for control in runnable_controls:
            started_at = utc_now()
            try:
                result = control.run(context)
            except Exception as error:  # Adapters are isolated; policy handles explicit errors.
                completed_at = utc_now()
                executions.append(
                    ControlExecution(
                        control_id=control.control_id,
                        control_version=control.control_version,
                        status=ExecutionStatus.ERROR,
                        started_at=started_at,
                        completed_at=completed_at,
                        applicable=True,
                        message=f"Adapter error: {type(error).__name__}",
                    )
                )
                continue
            executions.append(result.execution)
            findings.extend(result.findings)

        coverage_audit = audit_security_coverage(security_analysis_plan, executions)
        evaluated_findings, decision = evaluate(
            manifest=manifest,
            executions=tuple(executions),
            findings=tuple(findings),
            waivers=waivers,
            profile=profile,
        )
        completed_manifest = replace(manifest, completed_at=utc_now())
        return ScanResult(
            manifest=completed_manifest,
            executions=tuple(executions),
            findings=evaluated_findings,
            waivers=waivers,
            decision=decision,
            project_profile=project_profile,
            security_analysis_plan=security_analysis_plan,
            coverage_audit=coverage_audit,
        )


def configured_controls(profile: PolicyProfile, controls: Iterable[Control]) -> tuple[Control, ...]:
    """Retain controls with a policy entry; unknown adapters cannot silently affect a release."""
    return tuple(control for control in controls if control.control_id in profile.controls)
