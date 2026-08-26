"""Conservative GitHub Actions workflow security checks."""

from __future__ import annotations

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

_USES = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_WRITE_ALL = re.compile(r"(?m)^\s*permissions:\s*write-all\s*$")
_PRIVILEGED_TRIGGER = re.compile(r"(?m)^\s*(pull_request_target|workflow_run):")
_CHECKOUT = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*actions/checkout@")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class GitHubActionsSecurityControl:
    """Detect selected unsafe GitHub Actions workflow configurations."""

    control_id = "SEC-CICD-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        workflows = [
            path
            for path in context.inventory.files
            if path.relative_to(context.repository_root).parts[:2] == (".github", "workflows")
            and path.suffix.lower() in {".yaml", ".yml"}
        ]
        if not workflows:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.NOT_APPLICABLE,
                    started_at=started_at,
                    completed_at=utc_now(),
                    applicable=False,
                    message="No GitHub Actions workflow files were in the bounded inventory.",
                )
            )

        findings: list[Finding] = []
        for path in workflows:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read workflow: {relative}") from error
            findings.extend(_privileged_trigger_findings(self, text, relative))
            findings.extend(_write_permission_findings(self, text, relative))
            findings.extend(_unpinned_action_findings(self, text, relative))

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=f"Inspected {len(workflows)} GitHub Actions workflow files.",
            ),
            findings=tuple(findings),
        )


def _privileged_trigger_findings(
    control: GitHubActionsSecurityControl, text: str, relative: str
) -> list[Finding]:
    trigger = _PRIVILEGED_TRIGGER.search(text)
    checkout = _CHECKOUT.search(text)
    if trigger is None or checkout is None:
        return []
    location = Location(path=relative, start_line=_line_for(text, trigger.start()))
    evidence = {"trigger": trigger.group(1), "checkout": "actions/checkout"}
    return [
        Finding(
            rule_id=control.control_id,
            rule_version=control.control_version,
            title="Privileged workflow checks out repository content",
            message=(
                f"The workflow uses '{trigger.group(1)}' and checks out repository content. This can expose "
                "privileged tokens or secrets to untrusted pull-request content."
            ),
            remediation=(
                "Use an unprivileged pull_request workflow for untrusted code. If a privileged workflow is "
                "unavoidable, do not check out or execute pull-request-controlled content."
            ),
            severity=Severity.BLOCKER,
            confidence=Confidence.HIGH,
            fingerprint=fingerprint_for(control.control_id, location, evidence),
            location=location,
            evidence=evidence,
        )
    ]


def _write_permission_findings(
    control: GitHubActionsSecurityControl, text: str, relative: str
) -> list[Finding]:
    findings: list[Finding] = []
    for match in _WRITE_ALL.finditer(text):
        location = Location(path=relative, start_line=_line_for(text, match.start()))
        evidence = {"permissions": "write-all"}
        findings.append(
            Finding(
                rule_id=control.control_id,
                rule_version=control.control_version,
                title="GitHub Actions workflow grants write-all permissions",
                message="The workflow uses permissions: write-all instead of a least-privilege token scope.",
                remediation=(
                    "Set repository defaults to read-only and grant only the precise write permission required "
                    "by an individual job."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint=fingerprint_for(control.control_id, location, evidence),
                location=location,
                evidence=evidence,
            )
        )
    return findings


def _unpinned_action_findings(
    control: GitHubActionsSecurityControl, text: str, relative: str
) -> list[Finding]:
    findings: list[Finding] = []
    for match in _USES.finditer(text):
        reference = match.group(1)
        if reference.startswith(("./", "docker://")) or "@" not in reference:
            continue
        action, version = reference.rsplit("@", 1)
        if _FULL_SHA.fullmatch(version):
            continue
        location = Location(path=relative, start_line=_line_for(text, match.start()))
        evidence = {"action": action, "pin_type": "mutable_reference"}
        findings.append(
            Finding(
                rule_id=control.control_id,
                rule_version=control.control_version,
                title="Third-party GitHub Action is not pinned to a full commit SHA",
                message=(
                    f"The workflow references '{action}' through a mutable tag or branch rather than an "
                    "immutable full commit SHA."
                ),
                remediation=(
                    "Pin the action to a verified 40-character commit SHA and maintain that reference through "
                    "a reviewed dependency-update process."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint=fingerprint_for(control.control_id, location, evidence),
                location=location,
                evidence=evidence,
            )
        )
    return findings


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
