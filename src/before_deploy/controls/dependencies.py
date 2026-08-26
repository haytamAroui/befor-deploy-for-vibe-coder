"""Dependency manifest and lockfile presence checks."""

from __future__ import annotations

from pathlib import Path

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import (
    Confidence,
    ControlExecution,
    ExecutionStatus,
    Finding,
    Severity,
    fingerprint_for,
    utc_now,
)

_PYTHON_MANIFESTS = {"pyproject.toml", "Pipfile", "setup.py", "setup.cfg"}
_PYTHON_LOCKFILES = {"poetry.lock", "uv.lock", "Pipfile.lock", "requirements.lock", "requirements.txt"}
_NODE_LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"}


class DependencyLockfileControl:
    """Require a recognized lockfile when Python or Node manifests are present."""

    control_id = "SEC-DEP-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        relative_paths = {
            path.relative_to(context.repository_root).as_posix(): path for path in context.inventory.files
        }
        root_names = {Path(path).name for path in relative_paths}
        python_detected = bool(root_names & _PYTHON_MANIFESTS) or any(
            name.startswith("requirements") and name.endswith(".txt") for name in root_names
        )
        node_detected = "package.json" in root_names

        if not python_detected and not node_detected:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No supported Python or Node dependency manifest was detected.",
                )
            )

        findings: list[Finding] = []
        if python_detected and not (root_names & _PYTHON_LOCKFILES):
            findings.append(_missing_lockfile_finding(self, "python"))
        if node_detected and not (root_names & _NODE_LOCKFILES):
            findings.append(_missing_lockfile_finding(self, "node"))

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Inspected dependency manifests and root-level lockfiles.",
            ),
            findings=tuple(findings),
        )


def _missing_lockfile_finding(control: DependencyLockfileControl, ecosystem: str) -> Finding:
    evidence = {"ecosystem": ecosystem, "issue": "lockfile_missing"}
    return Finding(
        rule_id=control.control_id,
        rule_version=control.control_version,
        title=f"{ecosystem.title()} dependency lockfile is missing",
        message=(
            f"A supported {ecosystem} dependency manifest was detected without a recognized lockfile at "
            "repository root."
        ),
        remediation=(
            "Generate and commit the package manager's lockfile, then enforce deterministic dependency "
            "installation in continuous integration."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint=fingerprint_for(control.control_id, None, evidence),
        location=None,
        evidence=evidence,
    )
