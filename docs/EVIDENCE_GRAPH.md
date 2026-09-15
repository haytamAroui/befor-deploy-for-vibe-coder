# Evidence Graph v1

## Purpose

Evidence Graph v1 is the canonical typed lineage model connecting what Before Deploy observed, what deterministic controls executed, what they found, what policy decided, and what advisory providers produced.

It exists so later `inspect`, `investigate`, `explain`, remediation, verification, and release workflows can operate on explicit provenance instead of reconstructing relationships from prose.

The graph itself is **not** release authority:

```text
authority = EVIDENCE_GRAPH
gate_effect = NONE
```

Only a `POLICY_DECISION` node carries `RELEASE_AUTHORITY` in v1.

## Design rules

Evidence Graph v1 follows five rules:

1. **Typed nodes, not one mutable finding record.** Repository snapshots, observations, control executions, deterministic findings, waivers, policy decisions, advisory contexts, advisory executions, raw artifacts, normalized outputs, and advisory findings are separate node types.
2. **Content-addressed identity.** Every node ID is derived from the canonical immutable node payload. If a payload changes, its node ID changes.
3. **Explicit lineage edges only.** The base graph creates a relationship only when current data establishes that lineage directly.
4. **Authority is preserved, never upgraded by graph position.** Advisory nodes remain advisory regardless of downstream correlation.
5. **The graph digest binds the complete node/edge set.** Node or edge tampering invalidates `graph_sha256`.

## Node types

| Node type | Meaning | Authority |
| --- | --- | --- |
| `REPOSITORY_SNAPSHOT` | Redaction-safe identity of the deterministic scan input | `DETERMINISTIC_INPUT` |
| `POLICY_INPUT` | Policy name and exact policy digest | `DETERMINISTIC_POLICY_INPUT` |
| `OBSERVATION` | Existing deterministic `EvidenceSignal` | `DETERMINISTIC_EVIDENCE` |
| `CONTROL_EXECUTION` | One deterministic control execution | `DETERMINISTIC_EXECUTION` |
| `DETERMINISTIC_FINDING` | One normalized deterministic finding | `DETERMINISTIC_FINDING` |
| `WAIVER` | One narrowly scoped reviewed waiver | `DETERMINISTIC_WAIVER` |
| `POLICY_DECISION` | The deterministic release decision | `RELEASE_AUTHORITY` |
| `ADVISORY_CONTEXT` | Deterministic context identity consumed by a provider | `ADVISORY_CONTEXT` |
| `ADVISORY_EXECUTION` | Provider execution attestation | `ADVISORY_EXECUTION` |
| `RAW_ADVISORY_ARTIFACT` | Content-free identity of raw provider JSON | `ADVISORY_ARTIFACT` |
| `NORMALIZED_ADVISORY_OUTPUT` | Content-addressed normalized advisory-source result | `ADVISORY_ARTIFACT` |
| `ADVISORY_FINDING` | One normalized AI/third-party finding | `ADVISORY` |

Repository-local absolute paths are deliberately not copied into the graph. Source locations remain repository-relative.

## Base edge types

Evidence Graph v1 uses these directed lineage relations:

```text
DERIVED_FROM
OBSERVED_AT
PRODUCED_BY
SUPPORTS
APPLIES_TO
```

Examples:

```text
OBSERVATION --OBSERVED_AT--> REPOSITORY_SNAPSHOT
CONTROL_EXECUTION --DERIVED_FROM--> REPOSITORY_SNAPSHOT
DETERMINISTIC_FINDING --OBSERVED_AT--> REPOSITORY_SNAPSHOT
DETERMINISTIC_FINDING --PRODUCED_BY--> CONTROL_EXECUTION
WAIVER --APPLIES_TO--> DETERMINISTIC_FINDING
POLICY_DECISION --DERIVED_FROM--> POLICY_INPUT
POLICY_DECISION --DERIVED_FROM--> CONTROL_EXECUTION / FINDING / WAIVER
ADVISORY_EXECUTION --DERIVED_FROM--> ADVISORY_CONTEXT
RAW_ADVISORY_ARTIFACT --PRODUCED_BY--> ADVISORY_EXECUTION
NORMALIZED_ADVISORY_OUTPUT --DERIVED_FROM--> RAW_ADVISORY_ARTIFACT
ADVISORY_FINDING --DERIVED_FROM--> NORMALIZED_ADVISORY_OUTPUT
```

A deterministic finding is linked to a control execution only when `rule_id` and `rule_version` exactly match that execution's `control_id` and `control_version`.

## Content-addressed identity

Every node stores:

```text
node_type
node_id
payload_sha256
authority
<typed payload>
```

The node digest is SHA-256 over canonical JSON containing the node type, authority, and typed semantic payload. The node ID is:

```text
<lowercase-node-type>:<payload_sha256>
```

The graph stores `graph_sha256`, computed over the sorted node set and sorted edge set plus schema/authority metadata.

## Deterministic authority boundary

The graph does not convert a finding into a policy effect.

`DETERMINISTIC_FINDING` nodes contain the normalized detector result and policy-assigned disposition when present, but release authority remains represented separately by `POLICY_DECISION`.

```text
finding -> policy evaluation -> PolicyDecision
```

`gate_effect` is therefore not treated as an intrinsic property of a finding.

## Advisory lineage

PR24 and PR25 supply the advisory lineage anchors:

```text
ADVISORY_CONTEXT
        |
        v
ADVISORY_EXECUTION
        |
        v
RAW_ADVISORY_ARTIFACT
        |
        v
NORMALIZED_ADVISORY_OUTPUT
        |
        v
ADVISORY_FINDING
```

Advisory context, execution, and finding nodes are validated as gate-neutral. Their presence, severity, confidence, model identity, provider status, or graph connectivity can never create a deterministic release result.

For provider executions where no trustworthy raw artifact exists, `NORMALIZED_ADVISORY_OUTPUT` may be linked directly to `ADVISORY_EXECUTION` using `PRODUCED_BY`.

For imported advisory files without a live provider execution, raw and normalized artifact nodes preserve file-to-finding lineage without inventing an execution.

## PR27 correlation overlay

PR27 deliberately does **not** mutate the base lineage graph schema to pretend location overlap is lineage.

Instead it creates a deterministic overlay bound to the exact `graph_sha256`.

That overlay uses stable graph node IDs and emits diagnostic records shaped as:

```text
ADVISORY_FINDING --CORRELATES_WITH--> DETERMINISTIC_FINDING
basis = LOCATION_OVERLAP
authority = CORRELATION_DIAGNOSTIC
gate_effect = NONE
```

`CORRELATES_WITH` therefore means only that repository-relative line ranges overlap. It does not mean the two findings are semantically identical, mutually validating, or release-authoritative.

PR27 also creates an exact advisory deduplication view keyed only by the normalized advisory fingerprint. It never collapses different fingerprints merely because wording, severity, category, or source location look similar.

See [EVIDENCE_CORRELATION.md](EVIDENCE_CORRELATION.md) for the full contract.

## Validation

`validate_evidence_graph(...)` rejects:

- unsupported schema versions;
- graph container authority drift;
- duplicate or unsorted node identities;
- node payload/hash mismatches;
- node IDs that do not match their content digest;
- release authority on any node type other than `POLICY_DECISION`;
- advisory context/execution/finding gate effects other than `NONE`;
- unsupported base-graph relations;
- duplicate or unsorted edges;
- dangling edge endpoints;
- self-edges;
- graph digest mismatch.

Correlation overlay validation is separate and additionally checks graph binding, endpoint types, overlap coordinates, exact-fingerprint dedup groups, stable canonical IDs, and diagnostic-only authority.

## Redaction boundary

The graph may contain already-normalized deterministic/advisory finding text because those are existing redaction-safe report objects. It does not copy:

- repository-local absolute paths;
- raw source files;
- provider chain-of-thought;
- provider stdout/stderr;
- credentials;
- raw provider JSON content.

Raw advisory data is represented by hash, size, media type, and schema only.

The PR27 correlation overlay adds only graph node IDs, repository-relative overlap coordinates, exact advisory fingerprints, occurrence counts, and content digests.

## Current boundary

PR26 provides typed lineage identity. PR27 adds deterministic location correlation and exact advisory deduplication on top of those identities.

Neither increment adds:

- semantic similarity or embeddings;
- LLM-generated correlation;
- corroboration or confidence promotion;
- investigation or explanation commands;
- remediation or patching;
- verification or release disposition;
- any new release-policy behavior.

PR28 is the next increment: corroboration semantics that strengthen evidence interpretation without upgrading advisory authority.
