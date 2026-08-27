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

    lines.extend(["", "## Control execution", "", "| Control | Status | Version | Message |", "|---|---|---|---|"])
    for execution in sorted(result.executions, key=lambda item: item.control_id):
        lines.append(
            "| `{control}` | {status} | `{version}` | {message} |".format(
                control=_clean(execution.control_id),
                status=_clean(execution.status.value),
                version=_clean(execution.control_version),
                message=_clean(execution.message or "—"),
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


def _location_for(finding: Finding) -> str:
    if finding.location is None:
        return "repository-level"
    if finding.location.start_line is None:
        return finding.location.path
    return f"{finding.location.path}:{finding.location.start_line}"


def _clean(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
