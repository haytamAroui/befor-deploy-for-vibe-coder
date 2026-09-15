# Evidence inspection

## Purpose

PR29 adds a deterministic `before-deploy inspect` command over a persisted `review.json` artifact.

Inspection answers a narrow question:

> What exactly is recorded about this finding, where did it come from, what diagnostic relationships apply to it, and how—if at all—does a deterministic finding appear in the persisted policy decision?

Inspection does not rerun the repository scan, invoke an advisory provider, ask an LLM for an explanation, or recalculate release policy.

```text
authority = INSPECTION_DIAGNOSTIC
gate_effect = NONE
```

The persisted `POLICY_DECISION` remains the only release-authoritative node.

## Command

```text
before-deploy inspect <review.json> <selector>
```

Supported selectors are deliberately exact:

- a full Evidence Graph finding `node_id`;
- an exact deterministic or advisory finding fingerprint;
- an exact advisory `finding_id`.

Aliases must resolve to exactly one graph node. If an exact fingerprint is reused by multiple distinct graph nodes, inspection fails as ambiguous instead of choosing one by ordering or heuristic similarity.

Default output is terminal text. The command always writes:

```text
reports/inspect/inspection.json
reports/inspect/inspection.md
```

`--output-dir`, `--format json`, and `--format markdown` are supported.

A successful inspection exits `0`. Invalid/tampered artifacts or unresolved/ambiguous selectors exit `2`. Inspection never returns the persisted release outcome as its process exit code because inspection itself is not a gate.

## Persisted-artifact validation

`inspect` consumes the existing review artifact rather than rebuilding evidence from repository state.

Before selector resolution, PR29 reconstructs the typed PR26/27/28 models from the persisted JSON sections:

```text
evidence_graph
        |
        v
validate_evidence_graph

evidence_correlation
        |
        v
validate_evidence_correlation(graph)

evidence_corroboration
        |
        v
validate_evidence_corroboration(graph, correlation)
```

This preserves the existing validation contracts rather than creating a weaker JSON-only inspection path.

Tampering with graph IDs/digests, authority, gate effect, correlation derivation, corroboration provenance, or upstream bindings is rejected before inspection traversal.

The exact input `review.json` bytes are SHA-256 hashed as `source_review_sha256`, binding each inspection artifact to the review artifact that was actually read.

## Trace construction

Inspection begins with one selected finding node.

For an advisory finding, it includes:

```text
ADVISORY_FINDING
      |
      | DERIVED_FROM
      v
NORMALIZED_ADVISORY_OUTPUT
      |
      +--> RAW_ADVISORY_ARTIFACT --PRODUCED_BY--> ADVISORY_EXECUTION
      |                                             |
      |                                             | DERIVED_FROM
      |                                             v
      |                                       ADVISORY_CONTEXT
      |
      +--> provider-free imported source lineage when no execution exists
```

If PR27 recorded a location correlation, the corresponding deterministic finding is also included:

```text
ADVISORY_FINDING --CORRELATES_WITH--> DETERMINISTIC_FINDING
```

Inspection then follows the deterministic finding's recorded upstream lineage and relevant persisted policy context.

For a deterministic finding selected directly, the direction is symmetric for presentation: any PR27-correlated advisory claim is included with its advisory provenance.

## Exact-claim members

PR27 can contain multiple distinct advisory graph nodes with one exact normalized fingerprint.

When the selected or correlated advisory node belongs to an exact-deduplication group, inspection includes the group's recorded member nodes and its canonical node. This allows the trace to expose every persisted provenance path supporting the exact claim without deleting or rewriting occurrences.

Inspection does not broaden deduplication semantics. It uses only the exact PR27 group already present in the validated artifact.

## Policy context

Evidence Graph v1 records `POLICY_DECISION --DERIVED_FROM--> DETERMINISTIC_FINDING` for deterministic findings considered by policy.

PR29 renders an explicit relationship for each deterministic finding in the inspection trace:

```text
BLOCKING
WAIVER_REQUIRED
WAIVED
ADVISORY
EVALUATED
```

The relationship is derived only from the persisted `PolicyDecisionNode` fingerprint sets.

For an advisory selection, policy context belongs only to a correlated deterministic finding. The advisory finding itself is never described as a policy input merely because it overlaps a deterministic finding.

This distinction is explicit in Markdown and JSON output.

## Correlation and corroboration

Inspection carries through the validated PR27/28 diagnostic records that apply to the selected trace:

```text
correlation:
  LOCATION_OVERLAP only
  authority = CORRELATION_DIAGNOSTIC
  gate_effect = NONE

corroboration:
  exact-claim provenance facts only
  authority = CORROBORATION_DIAGNOSTIC
  gate_effect = NONE
```

Inspection does not reinterpret either layer.

A deterministic co-location remains context, not semantic agreement. Multi-provider or multi-model provenance remains provenance, not a probability or independent-vote claim.

## Inspection identity

Every inspection result records:

```text
source_review_sha256
graph_sha256
correlation_sha256
corroboration_sha256
selected_node_id
included nodes + roles + depths
included graph edges
applicable correlations
applicable exact-deduplication groups
applicable corroboration assessments
persisted policy relationships
authority = INSPECTION_DIAGNOSTIC
gate_effect = NONE
```

These fields are canonically hashed into `inspection_sha256`.

The digest is an integrity/reproducibility identifier for the derived inspection artifact. It is not an authenticity signature.

## Node roles

Nodes in `inspection.json` have one or more presentation roles:

```text
SELECTED
EXACT_CLAIM_MEMBER
CORRELATED_FINDING
LINEAGE
WAIVER
POLICY_DECISION
POLICY_INPUT
```

Roles are diagnostic labels. They do not alter the underlying graph node or authority.

Depth is presentation metadata describing traversal distance from the inspected finding/counterpart. It is not evidence strength.

## Privacy and content boundary

`inspect` reads the persisted review artifact but serializes only the validated graph/correlation/corroboration trace required for the selected finding.

In particular, it does not copy unrelated top-level review fields such as the legacy deterministic scan `repository_path` into `inspection.json`.

Raw source code and raw provider payloads are still not persisted by the Evidence Graph. Raw advisory artifacts remain represented by digest, size, media type, and schema metadata.

Normalized advisory messages are untrusted content. Markdown labels the selected advisory message accordingly; inspection never executes or interprets that content.

## Why inspection is not explanation

PR29 is intentionally mechanical.

It answers:

- which node was selected;
- what persisted lineage leads to it;
- what exact correlation/corroboration records reference it;
- what deterministic policy relationship is recorded.

It does **not** answer open-ended questions such as:

- why the code is vulnerable in natural-language reasoning;
- whether an advisory model is correct;
- how to exploit a defect;
- which remediation is best;
- whether the release should proceed beyond the existing deterministic policy result.

Those broader workflows belong to later `investigate` and `explain` increments and must remain advisory.

## CLI compatibility

PR29 changes the installed console-script target to a thin dispatcher.

```text
before_deploy.entrypoint:main
```

The dispatcher handles only `inspect`. All existing commands are delegated unchanged to the established `before_deploy.cli:main` implementation:

```text
scan      -> existing CLI
review    -> existing CLI
benchmark -> existing CLI
inspect   -> persisted evidence inspector
```

This avoids coupling inspection to scan/provider initialization and minimizes churn in the existing gate parser while the inspection surface is introduced.

## PR29 boundary

PR29 adds deterministic inspection only.

It does not add:

- an LLM call;
- semantic similarity;
- new correlation;
- new corroboration;
- adjusted confidence;
- a new release rule;
- policy reevaluation;
- repository rescanning;
- provider reruns;
- investigation sessions;
- natural-language explanation generation;
- remediation proposals;
- patching;
- verification;
- release disposition.

The next increment is PR30: `investigate`, which can use the stable inspection trace as bounded advisory context without becoming release authority.
