"""Unified developer-facing reports over deterministic and advisory review planes."""

from __future__ import annotations

from json import dumps

from before_deploy.advisory import UnifiedReviewResult
from before_deploy.evidence_correlation import (
    build_evidence_correlation,
    evidence_correlation_to_primitive,
)
from before_deploy.evidence_graph import build_evidence_graph, evidence_graph_to_primitive
from before_deploy.models import to_primitive


def render_review_json(result: UnifiedReviewResult) -> str:
    """Render a machine-readable review without allowing advisory findings into policy."""
    graph = build_evidence_graph(result.scan, result.advisory_sources)
    correlation = build_evidence_correlation(result, graph)
    payload = {
        "schema_version": 1,
        "authority_contract": {
            "release_authority": "deterministic_policy_decision",
            "advisory_authority": "ADVISORY",
            "advisory_gate_effect": "NONE",
            "correlation_semantics": "location_overlap_only",
            "deduplication_semantics": "exact_advisory_fingerprint_only",
            "correlation_authority": "diagnostic_only",
            "advisory_content_trust": "untrusted",
            "advisory_scope_attestation": "diagnostic_only",
            "advisory_execution_provenance": "diagnostic_only",
            "evidence_graph": "diagnostic_lineage_only",
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
        "evidence_graph": evidence_graph_to_primitive(graph),
        "evidence_correlation": evidence_correlation_to_primitive(correlation),
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_review_markdown(result: UnifiedReviewResult) -> str:
    """Render a human review summary with the trust boundary stated explicitly."""
    decision = result.scan.decision.outcome.value
    graph = build_evidence_graph(result.scan, result.advisory_sources)
    correlation = build_evidence_correlation(result, graph)
    nonmatched_scope = sum(
        source.scope_status not in {"MATCHED", "NOT_CHECKED"}
        for source in result.advisory_sources
    )
    duplicate_occurrences = sum(
        max(0, group.occurrence_count - 1) for group in correlation.duplicate_groups
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
        "- Evidence Graph v1 records typed lineage and has `gate_effect=NONE`.",
        "- Graph-backed correlation is diagnostic only and uses repository-relative location overlap.",
        "- Deduplication collapses only exact advisory fingerprints in a diagnostic unique view.",
        "- Correlation and deduplication never modify `PolicyDecision` or finding authority.",
        "",
        "## Summary",
        "",
        f"- Deterministic findings: **{len(result.scan.findings)}**",
        f"- Advisory finding occurrences: **{len(result.advisory_findings)}**",
        f"- Unique advisory claims: **{len(correlation.unique_advisory_node_ids)}**",
        f"- Exact duplicate advisory occurrences: **{duplicate_occurrences}**",
        f"- Advisory source errors: **{sum(source.status == 'ERROR' for source in result.advisory_sources)}**",
        f"- Advisory scope states other than MATCHED/NOT_CHECKED: **{nonmatched_scope}**",
        f"- Graph-backed location correlations: **{len(correlation.correlations)}**",
        f"- Evidence graph: **{len(graph.nodes)} nodes / {len(graph.edges)} edges**",
        f"- Evidence graph SHA-256: `{graph.graph_sha256}`",
        f"- Correlation SHA-256: `{correlation.correlation_sha256}`",
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

    if correlation.duplicate_groups:
        lines.extend(["## Exact advisory duplicates", ""])
        for group in correlation.duplicate_groups:
            lines.append(
                f"- `{group.fingerprint}` — occurrences **{group.occurrence_count}**, "
                f"canonical graph node `{group.canonical_node_id}`"
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
            item = correlation_map.get(finding.fingerprint)
            if item is not None:
                lines.append(
                    "- Deterministic location overlap: "
                    + ", ".join(f"`{value}`" for value in item.deterministic_fingerprints)
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
