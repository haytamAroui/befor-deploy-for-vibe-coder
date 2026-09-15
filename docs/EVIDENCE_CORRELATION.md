# Evidence correlation and exact deduplication

## Purpose

PR27 adds a deterministic diagnostic layer over Evidence Graph v1.

It answers two narrow questions:

1. Which advisory and deterministic finding nodes overlap at a repository-relative source location?
2. Which advisory finding occurrences are exact repeats of the same normalized advisory fingerprint?

Neither answer is release authority.

```text
authority = CORRELATION_DIAGNOSTIC
gate_effect = NONE
```

`PolicyDecision` remains the only release-authoritative result.

## Why correlation and deduplication are separate

Location overlap does not prove two findings describe the same defect.

Two tools can point at the same line for unrelated reasons. Therefore PR27 does not merge findings merely because they overlap.

Deduplication is stricter. PR27 collapses only exact repeated advisory fingerprints in a derived unique-claim view.

```text
correlation:
  repository-relative line ranges overlap
  -> diagnostic relationship only

exact deduplication:
  advisory fingerprint A == advisory fingerprint B
  -> one canonical diagnostic claim identity
```

Similar titles, categories, severities, messages, or colocated findings are not enough to deduplicate.

## Graph binding

The correlation result is bound to the exact Evidence Graph v1 digest:

```text
graph_sha256
        |
        v
EvidenceCorrelationResult
        |
        +--> CORRELATES_WITH records
        |
        +--> unique advisory node IDs
        |
        +--> exact duplicate groups
        |
        v
correlation_sha256
```

A result cannot be validated against a different graph digest.

This makes correlation inspectable without mutating the underlying lineage graph schema.

## Correlation identity

A graph-backed correlation record contains:

```text
correlation_id
source_node_id        # ADVISORY_FINDING
target_node_id        # DETERMINISTIC_FINDING
relation = CORRELATES_WITH
basis = LOCATION_OVERLAP
path
overlap_start_line
overlap_end_line
authority = CORRELATION_DIAGNOSTIC
gate_effect = NONE
```

The `correlation_id` is SHA-256-derived from the canonical record payload.

Direction is intentionally stable:

```text
ADVISORY_FINDING --CORRELATES_WITH--> DETERMINISTIC_FINDING
```

The direction is for serialization stability only. It does not imply authority flows from the deterministic finding into the advisory claim or vice versa.

## Location rule

Correlation requires all of the following:

- both endpoints are finding nodes;
- the source endpoint is advisory;
- the target endpoint is deterministic;
- both have repository-relative locations;
- both have line numbers;
- paths are exactly equal;
- closed line ranges overlap.

For ranges `[a_start, a_end]` and `[d_start, d_end]`, the overlap is:

```text
start = max(a_start, d_start)
end   = min(a_end, d_end)
```

A correlation exists only when `start <= end`.

No title, severity, category, confidence, provider, model, or message similarity participates in this rule.

## Exact advisory deduplication

The existing normalized advisory fingerprint is the only PR27 deduplication key.

The raw occurrence stream remains available in `advisory_findings`. PR27 adds a derived unique view rather than deleting source occurrences.

For each exact fingerprint group, the result records:

```text
group_id
fingerprint
canonical_node_id
member_node_ids
occurrence_count
basis = EXACT_ADVISORY_FINGERPRINT
authority = CORRELATION_DIAGNOSTIC
gate_effect = NONE
```

The canonical graph node is the lexicographically smallest node ID among nodes carrying that exact fingerprint. This rule is deterministic and independent of provider ordering.

A group is emitted only when there is a real duplicate:

- more than one advisory occurrence; or
- more than one graph node carrying the same exact fingerprint.

## What deduplication does not mean

Deduplication does not establish correctness, severity, exploitability, corroboration, or release impact.

It also does not collapse:

- differently worded findings;
- different fingerprints on the same line;
- similar categories;
- matching severity;
- findings from two providers that merely appear semantically related.

Those are stronger claims and are intentionally outside PR27.

## Review artifact

`review.json` now contains:

```text
evidence_graph

evidence_correlation:
  schema_version
  graph_sha256
  correlation_sha256
  authority
  gate_effect
  correlations[]
  unique_advisory_node_ids[]
  duplicate_groups[]
```

The older `correlations` field remains as a compatibility view over advisory/deterministic fingerprints. New graph-aware consumers should use `evidence_correlation`.

`review.md` reports:

- advisory occurrence count;
- unique advisory claim count;
- exact duplicate occurrence count;
- graph-backed location-correlation count;
- Evidence Graph digest;
- correlation digest.

## Validation

`validate_evidence_correlation(...)` rejects:

- unsupported schema versions;
- correlation results bound to another graph;
- authority or gate-effect upgrades;
- unsorted or duplicate correlation IDs;
- endpoints that are not advisory -> deterministic findings;
- missing or changed location overlap;
- unsupported correlation bases;
- non-advisory unique-claim node IDs;
- deduplication groups that contain no duplicate;
- canonical node instability;
- member nodes whose fingerprints differ;
- correlation/group IDs that do not match their canonical payload;
- correlation digest drift.

## Authority boundary

Correlation connectivity never feeds `PolicyDecision`.

```text
AdvisoryFinding
      |
      | LOCATION_OVERLAP
      v
DeterministicFinding

        does not imply

AdvisoryFinding -> BLOCK
AdvisoryFinding -> PASS
AdvisoryFinding -> deterministic confidence
```

PR28 can use the stable identities produced here to describe corroboration strength. Even then, corroboration must not upgrade advisory authority.

## PR27 boundary

PR27 adds deterministic correlation and exact deduplication only.

It does not add:

- semantic similarity;
- embeddings;
- LLM-generated correlation;
- corroboration scoring;
- confidence calibration;
- evidence-strength promotion;
- `inspect`, `investigate`, or `explain`;
- remediation or patching;
- verification or release disposition;
- any new deterministic release rule.

The next increment is PR28: corroboration semantics that can strengthen confidence/evidence interpretation without changing release authority.
