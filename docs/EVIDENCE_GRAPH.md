# Evidence Graph v1

## Purpose

Evidence Graph v1 is the canonical typed lineage model that connects what Before Deploy observed, what deterministic controls executed, what they found, what policy decided, and what advisory providers produced.

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
3. **Explicit edges only.** V1 creates a relationship only when current data establishes that lineage directly. It does not infer semantic equivalence.
4. **Authority is preserved, never upgraded by graph position.** Advisory nodes remain advisory even when connected to deterministic nodes in later graph versions.
5. **The graph digest binds the complete node/edge set.** Node or edge tampering invalidates `graph_sha256`.

## Node types

V1 defines these node types:

| Node type | Meaning | Authority |
| --- | --- | --- |
| `REPOSITORY_SNAPSHOT` | Redaction-safe identity of the deterministic scan input | `DETERMINISTIC_INPUT` |
| `POLICY_INPUT` | Policy name and exact policy digest | `DETERMINISTIC_POLICY_INPUT` |
| `OBSERVATION` | Existing deterministic `EvidenceSignal` from repository/requirement/infrastructure evidence | `DETERMINISTIC_EVIDENCE` |
| `CONTROL_EXECUTION` | One deterministic control execution | `DETERMINISTIC_EXECUTION` |
| `DETERMINISTIC_FINDING` | One normalized deterministic finding | `DETERMINISTIC_FINDING` |
| `WAIVER` | One narrowly scoped reviewed waiver | `DETERMINISTIC_WAIVER` |
| `POLICY_DECISION` | The deterministic release decision | `RELEASE_AUTHORITY` |
| `ADVISORY_CONTEXT` | PR24 deterministic context identity consumed by a provider | `ADVISORY_CONTEXT` |
| `ADVISORY_EXECUTION` | PR25 provider execution attestation | `ADVISORY_EXECUTION` |
| `RAW_ADVISORY_ARTIFACT` | Content-free identity of raw provider JSON | `ADVISORY_ARTIFACT` |
| `NORMALIZED_ADVISORY_OUTPUT` | Content-addressed normalized advisory-source result | `ADVISORY_ARTIFACT` |
| `ADVISORY_FINDING` | One normalized AI/third-party finding | `ADVISORY` |

Repository-local absolute paths are deliberately not copied into the graph. Source locations remain repository-relative.

## Edge types

V1 reserves these directed relations:

```text
DERIVED_FROM
OBSERVED_AT
PRODUCED_BY
SUPPORTS
APPLIES_TO
```

Current builder behavior is deliberately conservative.

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

A deterministic finding is linked to a control execution only when `rule_id` and `rule_version` exactly match that execution's `control_id` and `control_version`. V1 does not guess producers from titles, paths, or semantic similarity.

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

This makes node identity immutable by construction. Editing a title, execution timestamp, location, provider identity, configuration digest, or any other semantic field without recomputing the identity is detected by validation.

The graph itself stores `graph_sha256`, computed over the sorted node set and sorted edge set plus schema/authority metadata.

## Deterministic authority boundary

The graph does not convert a finding into a policy effect.

`DETERMINISTIC_FINDING` nodes contain the finding's normalized detector result and policy-assigned disposition when present, but release authority remains represented separately by the `POLICY_DECISION` node.

This preserves the architecture:

```text
finding -> policy evaluation -> PolicyDecision
```

rather than treating `gate_effect` as an intrinsic property of a finding.

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

For imported advisory files without a live provider execution, raw and normalized artifact nodes still preserve file-to-finding lineage without inventing an execution.

## Correlation is intentionally not in v1

Before Deploy already has a narrow location-overlap review correlation. Evidence Graph v1 deliberately does **not** convert that into a `CORRELATES_WITH` edge.

PR27 owns correlation and deduplication semantics. That increment can add explicit correlation nodes/edges only after defining identity, evidence strength, and deduplication rules. Two findings appearing on the same line are not automatically the same claim.

Likewise, PR28 will define corroboration without upgrading authority.

## Validation

`validate_evidence_graph(...)` rejects:

- unsupported schema versions;
- graph container authority drift;
- duplicate or unsorted node identities;
- node payload/hash mismatches;
- node IDs that do not match their content digest;
- release authority on any node type other than `POLICY_DECISION`;
- advisory context/execution/finding gate effects other than `NONE`;
- unsupported relations;
- duplicate or unsorted edges;
- dangling edge endpoints;
- self-edges;
- graph digest mismatch.

## Redaction boundary

The graph may contain already-normalized deterministic/advisory finding text because those are existing redaction-safe report objects. It does not copy:

- repository-local absolute path;
- raw source files;
- provider chain-of-thought;
- provider stdout/stderr;
- credentials;
- raw provider JSON content.

Raw advisory data is represented by hash, size, media type, and schema only.

## PR26 boundary

PR26 adds the graph schema, builder, validators, and renderers. It does not add:

- semantic correlation or deduplication;
- corroboration scoring;
- an AI-generated graph edge;
- investigation or explanation commands;
- remediation proposals;
- patching;
- verification/release disposition;
- any new release-policy behavior.

The next increment is PR27: deterministic correlation/deduplication on top of stable graph identities. PR28 then adds corroboration semantics without authority upgrades.
