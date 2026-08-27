"""Human-readable, redaction-safe Markdown release reports."""

from __future__ import annotations

from collections import defaultdict

from before_deploy.models import Finding, ScanResult


def render_markdown(result: ScanResult) -> str:
    """Render a review-oriented report without including raw secret material."""
    manifest = result.manifest
    decision = result.decision
    lines = [
        "# Before Deploy Security Report",
        "",
        "## Gate decision",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Outcome | **{decision.outcome.value}** |",
        f"| Scan ID | `{manifest.scan_id}` |",
        f"| Repository digest | `{manifest.repository_digest}` |",
        f"| Git revision | `{manifest.git_revision or 'not available'}` |",
        f"| Policy | `{manifest.policy_name}` (`{manifest.policy_digest}`) |",
        f"| Scanned files | {manifest.scanned_file_count} |",
        f"| Excluded files | {manifest.excluded_file_count} |",
        "",
        "## Decision rationale",
        "",
    ]
    if decision.reason_codes:
        lines.extend(f"- `{_clean(reason)}`" for reason in decision.reason_codes)
    else:
        lines.append("- No decision reason codes were generated.")

    profile = result.project_profile
    if profile is not None:
        lines.extend(
            [
                "",
                "## Adaptive project profile",
                "",
                "| Field | Detected value |",
                "|---|---|",
                f"| Languages | {_clean(', '.join(profile.languages) or 'none')} |",
                f"| Frameworks | {_clean(', '.join(profile.frameworks) or 'none')} |",
                f"| Package managers | {_clean(', '.join(profile.package_managers) or 'none')} |",
            ]
        )
        if profile.coverage_gaps:
            lines.extend(["", "### Coverage gaps", ""])
            lines.extend(f"- {_clean(gap)}" for gap in profile.coverage_gaps)

    plan = result.security_analysis_plan
    if plan is not None:
        lines.extend(
            [
                "",
                "## Security analysis plan",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Plan version | `{_clean(plan.plan_version)}` |",
                f"| Profile version | `{_clean(plan.profile_version)}` |",
                f"| Capability catalog | `{_clean(plan.catalog_version)}` (`{_clean(plan.catalog_digest)}`) |",
                f"| Security domain catalog | `{_clean(plan.security_domain_catalog_version or 'unavailable')}` (`{_clean(plan.security_domain_catalog_digest or 'unavailable')}`) |",
                f"| Policy provenance | `{_clean(plan.policy_name)}` (`{_clean(plan.policy_digest)}`) |",
                f"| Evidence signals | {len(plan.evidence)} |",
            ]
        )
        selections = (*plan.control_selections, *plan.adapter_selections, *plan.skill_selections)
        lines.extend(["", "### Selected approved capabilities", ""])
        if selections:
            lines.extend(
                [
                    "| Kind | Capability | Implementation | Version | Evidence | Rationale |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for selection in selections:
                lines.append(
                    "| {kind} | `{capability}` | `{implementation}` | `{version}` | {evidence} | {rationale} |".format(
                        kind=_clean(selection.kind),
                        capability=_clean(selection.capability_id),
                        implementation=_clean(selection.implementation_id),
                        version=_clean(selection.capability_version),
                        evidence=_clean(", ".join(selection.evidence_ids) or "repository-wide"),
                        rationale=_clean(selection.rationale),
                    )
                )
        else:
            lines.append("- No approved capabilities were selected.")
        lines.extend(["", "### Selected control contracts", ""])
        if plan.control_contract_selections:
            lines.extend(
                [
                    "| Control contract | Capability | Implementation | Domains | Scope | Exclusions |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for contract in plan.control_contract_selections:
                lines.append(
                    "| `{control}` (`{version}`) | `{capability}` | `{implementation}` | {domains} | {scope} | {exclusions} |".format(
                        control=_clean(contract.control_id),
                        version=_clean(contract.control_version),
                        capability=_clean(contract.capability_id),
                        implementation=_clean(contract.implementation_id),
                        domains=_clean(", ".join(contract.security_domain_ids)),
                        scope=_clean(contract.detection_scope),
                        exclusions=_clean("; ".join(contract.exclusions) or "—"),
                    )
                )
        else:
            lines.append("- No reviewed control contracts were selected.")
        if plan.coverage_expectations:
            lines.extend(["", "### Coverage expectations", ""])
            lines.extend(["| Domain | Domain ID | Evidence | Rationale |", "|---|---|---|---|"])
            for expectation in plan.coverage_expectations:
                lines.append(
                    "| {domain} | `{domain_id}` | {evidence} | {rationale} |".format(
                        domain=_clean(expectation.domain),
                        domain_id=_clean(expectation.domain_id or "—"),
                        evidence=_clean(", ".join(expectation.evidence_ids)),
                        rationale=_clean(expectation.rationale),
                    )
                )
        if plan.exclusions:
            lines.extend(["", "### Plan exclusions", ""])
            lines.extend(f"- {_clean(exclusion)}" for exclusion in plan.exclusions)

    coverage_audit = result.coverage_audit
    if coverage_audit is not None:
        lines.extend(["", "## Coverage audit", ""])
        lines.append(
            "Coverage is diagnostic only. `COVERED` means the mapped selected capabilities completed; "
            "it is not a claim of exhaustive analysis or a gate decision."
        )
        lines.extend(["", "| Domain | Domain ID | Status | Capabilities | Evidence | Rationale |", "|---|---|---|---|---|---|"])
        for assessment in coverage_audit.assessments:
            lines.append(
                    "| {domain} | `{domain_id}` | **{status}** | {capabilities} | {evidence} | {rationale} |".format(
                        domain=_clean(assessment.domain),
                        domain_id=_clean(assessment.domain_id or "—"),
                        status=_clean(assessment.status.value),
                    capabilities=_clean(", ".join(assessment.capability_ids) or "—"),
                    evidence=_clean(", ".join(assessment.evidence_ids) or "—"),
                    rationale=_clean(assessment.rationale),
                )
            )

    lines.extend(
        [
            "",
            "## Control execution",
            "",
            "| Control | Status | Version | Message | Metadata |",
            "|---|---|---|---|---|",
        ]
    )
    for execution in sorted(result.executions, key=lambda item: item.control_id):
        lines.append(
            "| `{control}` | {status} | `{version}` | {message} | {metadata} |".format(
                control=_clean(execution.control_id),
                status=_clean(execution.status.value),
                version=_clean(execution.control_version),
                message=_clean(execution.message or "—"),
                metadata=_metadata_for(execution.metadata),
            )
        )

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        grouped[finding.disposition.value if finding.disposition else "UNCLASSIFIED"].append(finding)

    for disposition in ("BLOCK", "WAIVER_REQUIRED", "WARN", "UNCLASSIFIED"):
        findings = grouped.get(disposition, [])
        if not findings:
            continue
        lines.extend(["", f"## {disposition} findings", ""])
        for finding in sorted(findings, key=lambda item: (item.rule_id, item.fingerprint)):
            location = _location_for(finding)
            waiver_note = " (waived)" if finding.fingerprint in decision.waived_fingerprints else ""
            lines.extend(
                [
                    f"### `{_clean(finding.rule_id)}` — {_clean(finding.title)}{waiver_note}",
                    "",
                    f"**Location:** `{_clean(location)}`  ",
                    f"**Severity:** {_clean(finding.severity.value)}  ",
                    f"**Confidence:** {_clean(finding.confidence.value)}  ",
                    f"**Fingerprint:** `{_clean(finding.fingerprint)}`",
                    "",
                    _clean(finding.message),
                    "",
                    f"**Remediation:** {_clean(finding.remediation)}",
                    "",
                ]
            )

    if result.waivers:
        lines.extend(["## Loaded waivers", ""])
        for waiver in result.waivers:
            lines.append(
                f"- `{_clean(waiver.waiver_id)}` for `{_clean(waiver.rule_id)}` expires "
                f"{waiver.expires_at.isoformat()}"
            )
        lines.append("")

    lines.extend(["## Scan limitations", ""])
    lines.extend(f"- {_clean(limitation)}" for limitation in manifest.limitations)
    lines.extend(
        [
            "",
            "> This report records automated, scope-limited technical controls. It is not a compliance "
            "certification, penetration-test result, or guarantee that the target system is secure.",
            "",
        ]
    )
    return "\n".join(lines)


def _metadata_for(metadata: dict[str, str] | object) -> str:
    if not isinstance(metadata, dict):
        metadata = dict(metadata)
    if not metadata:
        return "—"
    return _clean("; ".join(f"{key}={value}" for key, value in sorted(metadata.items())))


def _location_for(finding: Finding) -> str:
    if finding.location is None:
        return "repository-level"
    if finding.location.start_line is None:
        return finding.location.path
    return f"{finding.location.path}:{finding.location.start_line}"


def _clean(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
