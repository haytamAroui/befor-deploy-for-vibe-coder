# Evidence corroboration

## Purpose

PR28 adds a provenance-aware diagnostic interpretation layer over Evidence Graph v1 and PR27 correlation/deduplication.

It answers a deliberately narrow question:

> For one exact normalized advisory claim, what repetition and provenance facts are available to help a human interpret it?

It does **not** answer whether the claim is true, whether its severity is correct, or whether a release should pass.

```text
authority = CORROBORATION_DIAGNOSTIC
gate_effect = NONE
```

`PolicyDecision` remains the only release-authoritative result.

## Why corroboration is not confidence calibration

Provider confidence is not treated as a calibrated probability.

PR28 does not add numbers to it, average confidence across providers, convert deterministic findings into an AI confidence boost, or overwrite the original advisory finding.

Instead, corroboration records inspectable facts:

- exact normalized claim repetition;
- distinct normalized-output provenance;
- distinct advisory executions;
- provider diversity;
- attested model diversity;
- deterministic source-location co-location.

These facts can make an advisory claim more useful to investigate while leaving its authority unchanged.

## Exact-claim boundary

Advisory corroboration starts only from PR27's canonical exact advisory claim identities.

PR28 does not use:

- embeddings;
- title similarity;
- message similarity;
- category similarity;
- severity similarity;
- same-line proximity between two different advisory fingerprints;
- an LLM judgment that two findings mean the same thing.

If two advisory findings have different normalized fingerprints, PR28 does not combine them into one corroboration assessment.

## Status model

Each canonical advisory claim receives exactly one status:

```text
NONE
REPEATED_EXACT_CLAIM
MULTI_EXECUTION_EXACT_CLAIM
```

The derivation is deterministic:

```text
if distinct advisory execution nodes >= 2:
    MULTI_EXECUTION_EXACT_CLAIM
elif exact advisory occurrence count >= 2:
    REPEATED_EXACT_CLAIM
else:
    NONE
```

The statuses are qualitative diagnostics, not probabilities and not policy effects.

`MULTI_EXECUTION_EXACT_CLAIM` means only that the same exact normalized claim is backed by more than one recorded execution lineage. It does not assert that those executions are statistically independent.

## Signals

An assessment may contain these signals:

```text
EXACT_REPEAT
MULTI_NORMALIZED_OUTPUT
MULTI_EXECUTION
MULTI_PROVIDER
MULTI_ATTESTED_MODEL
DETERMINISTIC_COLOCATION
```

### Exact repeat

`EXACT_REPEAT` means the normalized advisory fingerprint occurred more than once in the review occurrence stream.

This can happen with imported files or live provider executions. Repetition alone does not establish independence.

### Multiple normalized outputs

`MULTI_NORMALIZED_OUTPUT` means the canonical exact claim has lineage to more than one normalized advisory output node.

### Multiple executions

`MULTI_EXECUTION` means the exact claim traces to more than one `ADVISORY_EXECUTION` node.

This is the basis for `MULTI_EXECUTION_EXACT_CLAIM`.

### Provider diversity

`MULTI_PROVIDER` is emitted when those execution nodes contain more than one distinct provider ID.

Provider diversity is recorded as a provenance fact. It does not create release authority and does not prove independence.

### Attested model diversity

`MULTI_ATTESTED_MODEL` is emitted only when at least two distinct provider/model identities are explicitly `ATTESTED` in execution provenance.

Unattested model names are never guessed or counted as model diversity.

### Deterministic co-location

`DETERMINISTIC_COLOCATION` means PR27 has a graph-backed location correlation from the canonical advisory node to at least one deterministic finding node.

This is contextual evidence only.

```text
ADVISORY_FINDING --CORRELATES_WITH--> DETERMINISTIC_FINDING
basis = LOCATION_OVERLAP
```

Co-location does **not** assert semantic equivalence. A deterministic finding on the same line can describe a different defect.

Most importantly, deterministic co-location **does not change corroboration status**. A single advisory claim that merely overlaps a deterministic finding remains:

```text
status = NONE
signals = [DETERMINISTIC_COLOCATION]
```

This prevents deterministic release authority from leaking into the advisory plane through graph connectivity.

## Provenance traversal

PR28 derives execution provenance from existing Evidence Graph lineage:

```text
ADVISORY_FINDING
        |
        | DERIVED_FROM
        v
NORMALIZED_ADVISORY_OUTPUT
        |
        +--> PRODUCED_BY --> ADVISORY_EXECUTION
        |
        +--> DERIVED_FROM --> RAW_ADVISORY_ARTIFACT
                               |
                               +--> PRODUCED_BY --> ADVISORY_EXECUTION
```

Imported advisory files without live execution provenance can still produce `REPEATED_EXACT_CLAIM`, but they cannot claim `MULTI_EXECUTION` or provider/model diversity.

## Stable identity and binding

`EvidenceCorroborationResult` is bound to both upstream digests:

```text
graph_sha256
correlation_sha256
        |
        v
EvidenceCorroborationResult
        |
        +--> AdvisoryCorroborationAssessment[]
        |
        v
corroboration_sha256
```

Every assessment has a SHA-256-derived `assessment_id` over its canonical semantic payload.

The result digest binds:

- graph digest;
- correlation digest;
- diagnostic authority metadata;
- complete sorted assessment set.

## Assessment fields

Each canonical exact advisory claim records:

```text
assessment_id
advisory_node_id
status
signals[]
occurrence_count
claim_member_node_ids[]
normalized_output_node_ids[]
execution_node_ids[]
provider_ids[]
attested_model_identities[]
deterministic_colocation_node_ids[]
authority = CORROBORATION_DIAGNOSTIC
gate_effect = NONE
```

There is deliberately no `effective_confidence`, `adjusted_severity`, `gate_effect`, `block`, or `pass` derivation beyond the fixed neutral authority fields.

## Validation

`validate_evidence_corroboration(...)` rejects:

- unsupported schema versions;
- graph-digest mismatch;
- correlation-digest mismatch;
- authority or gate-effect upgrades;
- missing or duplicate canonical advisory assessments;
- unsupported statuses or signals;
- any assessment that does not exactly match provenance re-derived from the graph/correlation inputs;
- result-digest drift.

This means a consumer cannot change a corroboration status, add a fake provider/model, invent an execution, or upgrade authority without invalidating the artifact.

## Review artifact

`review.json` adds:

```text
evidence_corroboration:
  schema_version
  graph_sha256
  correlation_sha256
  corroboration_sha256
  authority
  gate_effect
  assessments[]
```

The authority contract explicitly states:

```text
corroboration_semantics = exact_claim_provenance_only
corroboration_authority = diagnostic_only
deterministic_colocation_semantics = context_not_semantic_agreement
```

`review.md` summarizes repeated exact claims, multi-execution exact claims, deterministic co-location context, provider/model provenance, and the corroboration digest.

## Authority boundary

Corroboration cannot feed deterministic release authority:

```text
AdvisoryFinding
      |
      v
Correlation / Deduplication
      |
      v
Corroboration
      |
      X
PolicyDecision
```

The deterministic policy engine remains the only component that may produce release-authoritative `PASS`, `BLOCK`, or `ERROR` outcomes.

An organization may later define deterministic workflow policy that requires human review of advisories. That policy would gate on missing human-review evidence, not on an AI severity or corroboration level becoming release authority.

## PR28 boundary

PR28 adds provenance-aware corroboration diagnostics only.

It does not add:

- semantic similarity;
- confidence calibration;
- numeric corroboration scores;
- severity promotion;
- AI release authority;
- human-review attestations;
- `inspect`, `investigate`, or `explain`;
- remediation proposals or patching;
- verification or release disposition.

The next increment is PR29: `inspect`, using stable graph, correlation, and corroboration identities to present one claim and its complete traceable lineage.
