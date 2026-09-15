"""Unified developer-facing reports over deterministic and advisory review planes."""

from __future__ import annotations

from json import dumps

from before_deploy.advisory import UnifiedReviewResult
from before_deploy.models import to_primitive


def render_review_json(result: UnifiedReviewResult) -> str:
    """Render a machine-readable review without allowing advisory findings into policy."""
    payload = {
        "schema_version": 1,
        "authority_contract": {
            "release_authority": "deterministic_policy_decision",
            "advisory_authority": "ADVISORY",
            "advisory_gate_effect": "NONE",
            "correlation_semantics": "location_overlap_only",
            "advisory_content_trust": "untrusted",
            "advisory_scope_attestation": "diagnostic_only",
            "advisory_execution_provenance": "diagnostic_only",
        },
        "deterministic_scan": to_primitive(result.scan),
        "advisory_sources": [
            {
                "input_name": source.input_name,
                "source": source.source,
                "source_format": source.source_format,
                "finding_count": len(source.findings),
                "status": source.status,
                "message": source.message,
                "scope_status": source.scope_status,
                "scope_message": source.scope_message,
                "raw_artifact": to_primitive(source.raw_artifact),
                "execution": to_primitive(source.execution),
            }
            for source in result.advisory_sources
        ],
        "advisory_findings": to_primitive(result.advisory_findings),
        "correlations": to_primitive(result.correlations),
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_review_markdown(result: UnifiedReviewResult) -> str:
    """Render a human review summary with the trust boundary stated explicitly."""
    decision = result.scan.decision.outcome.value
    nonmatched_scope = sum(
        source.scope_status not in {"MATCHED", "NOT_CHECKED"}
        for source in result.advisory_sources
    )
    lines = [
        "# Before Deploy Unified Review",
        "",
        f"**Deterministic release decision:** `{decision}`",
        "",
        "## Authority contract",
        "",
        "- Only the deterministic `PolicyDecision` can affect release status.",
        "- Imported AI or third-party findings are `ADVISORY` with `gate_effect=NONE`.",
        "- Advisory message content is untrusted input and is not deterministic evidence.",
        "- Advisory scope attestation is diagnostic only and cannot change release status.",
        "- Advisory execution provenance is diagnostic lineage, not release authority.",
        "- Correlation means source-location overlap only; it does not prove semantic agreement.",
        "",
        "## Summary",
        "",
        f"- Deterministic findings: **{len(result.scan.findings)}**",
        f"- Advisory findings: **{len(result.advisory_findings)}**",
        f"- Advisory source errors: **{sum(source.status == 'ERROR' for source in result.advisory_sources)}**",
        f"- Advisory scope states other than MATCHED/NOT_CHECKED: **{nonmatched_scope}**",
        f"- Location correlations: **{len(result.correlations)}**",
        "",
    ]

    if result.advisory_sources:
        lines.extend(["## Advisory sources", ""])
        for source in result.advisory_sources:
            lines.append(
                f"- `{source.input_name}` — `{source.source}` / `{source.source_format}` "
                f"— `{source.status}` ({len(source.findings)} findings) "
                f"— scope `{source.scope_status}`"
            )
            if source.message:
                lines.append(f"  - Source: {source.message}")
            if source.scope_message:
                lines.append(f"  - Scope: {source.scope_message}")
            if source.execution is not None:
                execution = source.execution
                version = execution.implementation_version or "UNATTESTED"
                model = (
                    f"{execution.model.provider}/{execution.model.model}"
                    if execution.model.status == "ATTESTED"
                    else "UNATTESTED"
                )
                lines.append(
                    f"  - Execution: provider=`{execution.provider_id}`, "
                    f"implementation=`{execution.implementation}@{version}`, model=`{model}`, "
                    f"duration_ms=`{execution.duration_ms}`"
                )
                lines.append(
                    f"  - Lineage: context=`{execution.context_sha256}`, "
                    f"config=`{execution.configuration_sha256}`, "
                    f"normalized=`{execution.normalized_output_sha256}`"
                )
                if execution.raw_output is not None:
                    lines.append(
                        f"  - Raw output: sha256=`{execution.raw_output.sha256}`, "
                        f"bytes=`{execution.raw_output.size_bytes}`"
                    )
        lines.append("")

    if result.advisory_findings:
        correlation_map = {item.advisory_fingerprint: item for item in result.correlations}
        lines.extend(["## Advisory findings", ""])
        for finding in result.advisory_findings:
            location = _location_text(finding.location)
            lines.append(
                f"### [{finding.severity.upper()}] [{finding.category}] {finding.title}"
            )
            lines.append("")
            lines.append(f"- Source: `{finding.source}`")
            lines.append(f"- Authority: `{finding.authority}`")
            lines.append(f"- Gate effect: `{finding.gate_effect}`")
            if location:
                lines.append(f"- Location: `{location}`")
            if finding.confidence:
                lines.append(f"- Confidence: `{finding.confidence}`")
            correlation = correlation_map.get(finding.fingerprint)
            if correlation is not None:
                lines.append(
                    "- Deterministic location overlap: "
                    + ", ".join(f"`{item}`" for item in correlation.deterministic_fingerprints)
                )
                lines.append("- Correlation note: location overlap only; authority is unchanged.")
            lines.extend(["", finding.message, ""])
    else:
        lines.extend(["## Advisory findings", "", "No advisory findings were imported.", ""])

    return "\n".join(lines).rstrip() + "\n"


def _location_text(location) -> str:
    if location is None:
        return ""
    if location.start_line is None:
        return location.path
    if location.end_line is None or location.end_line == location.start_line:
        return f"{location.path}:{location.start_line}"
    return f"{location.path}:{location.start_line}-{location.end_line}"
