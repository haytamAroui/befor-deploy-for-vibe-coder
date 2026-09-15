# Evidence investigation

## Purpose

PR30 adds a bounded advisory investigation workflow on top of the validated PR29 inspection trace.

The workflow is intentionally split into two deterministic stages:

```text
persisted review.json
        |
        v
validated Evidence Graph / correlation / corroboration
        |
        v
PR29 inspection trace
        |
        v
investigation request packet
        |
        | external human / agent / model may reason here
        v
strict structured response
        |
        v
normalized investigation artifact
```

Neither the request nor the investigation result is release authority.

```text
request authority = INVESTIGATION_CONTEXT
investigation authority = INVESTIGATION_ADVISORY
gate_effect = NONE
```

`PolicyDecision` remains the only release-authoritative result.

## CLI

Create a bounded request packet without invoking any provider:

```bash
before-deploy investigate reports/review.json ADV-1 \
  --output-dir reports/investigate
```

This writes:

- `investigation-request.json`
- `investigation-request.md`

To import a structured external response:

```bash
before-deploy investigate reports/review.json ADV-1 \
  --response-file /tmp/investigation-response.json \
  --output-dir reports/investigate
```

This additionally writes:

- `investigation.json`
- `investigation.md`

The command returns `0` for a valid request/result and `2` for invalid input. It never derives an exit code from the investigation content.

## Why the command starts from `review.json`

`investigate` does not trust a free-standing prompt or arbitrary repository path.

It reloads the persisted PR26/27/28 evidence structures, runs their validators, and deterministically rebuilds the PR29 inspection for the requested selector.

That gives the request a complete binding chain:

```text
source_review_sha256
        |
graph_sha256
        |
correlation_sha256
        |
corroboration_sha256
        |
inspection_sha256
        |
request_sha256
```

A response must echo both `inspection_sha256` and `request_sha256` exactly.

This prevents a response generated for one finding or one evidence snapshot from being silently attached to another.

## Bounded context

The investigation request contains the complete validated PR29 inspection trace and an explicit `allowed_evidence_node_ids` list.

Every imported hypothesis, advisory observation, and open question must reference at least one node from that allow-list.

A response that references any other node ID is rejected.

Therefore an investigator cannot silently widen the evidentiary basis from:

```text
validated inspection trace
```

to:

```text
arbitrary repository path
unseen graph node
external claim with no recorded lineage
```

External research or additional repository evidence may be useful in a future investigation provider, but it must first become an explicit typed artifact with its own provenance. PR30 does not smuggle it in as an evidence reference.

## Request artifact

`investigation-request.json` contains:

```text
schema_version
source_review_sha256
graph_sha256
correlation_sha256
corroboration_sha256
inspection_sha256
request_sha256
selected_node_id
allowed_evidence_node_ids[]
authority = INVESTIGATION_CONTEXT
gate_effect = NONE
inspection_context
response_contract
```

The `request_sha256` is canonical SHA-256 over the bound inspection context and request metadata, excluding only the digest slot itself.

The request is deterministic for the same persisted evidence and selector.

## Structured response schema

PR30 accepts one strict schema only.

```json
{
  "schema_version": 1,
  "inspection_sha256": "<exact digest from request>",
  "request_sha256": "<exact digest from request>",
  "source": {
    "provider": "example-investigator",
    "model": "optional-declared-model"
  },
  "hypotheses": [
    {
      "statement": "A possible explanation to test.",
      "rationale": "Why this hypothesis follows from the bounded trace.",
      "evidence_node_ids": ["advisory_finding:..."]
    }
  ],
  "observations": [
    {
      "statement": "An advisory observation made from the bounded trace.",
      "evidence_node_ids": ["deterministic_finding:..."]
    }
  ],
  "questions": [
    {
      "question": "What remains unresolved?",
      "evidence_node_ids": ["control_execution:..."]
    }
  ]
}
```

Each item may contain only its documented fields.

Provider-supplied item IDs are not accepted. Before Deploy computes content-addressed IDs after normalization.

## Strict non-authority schema

Unknown response fields are rejected rather than ignored.

This is deliberate. In particular, an external investigator cannot add fields such as:

```text
authority
release_decision
gate_effect
severity
confidence
effective_confidence
policy_decision
```

and have them preserved as meaningful investigation metadata.

The only investigator-authored semantic structures in PR30 are:

- hypotheses;
- advisory observations;
- open questions;
- rationale text;
- references to allow-listed inspection nodes.

PR30 does not accept a provider-authored verdict.

## Item identity

Before Deploy assigns IDs from canonical normalized content:

```text
investigation-hypothesis:<sha256>
investigation-observation:<sha256>
investigation-question:<sha256>
```

Exact duplicate semantic items collapse to one canonical item in the normalized result.

Ordering from the external response does not determine identity.

## Investigator identity

The response may declare:

- provider name;
- optional model name.

Those values are recorded as:

```text
identity_status = DECLARED_UNATTESTED
```

PR30 does not pretend an arbitrary JSON response cryptographically proves which provider or model generated it.

Future live provider integrations may add stronger execution attestations, but they must not retroactively upgrade this declaration.

## Raw-to-normalized lineage

The importer records both:

```text
raw_input_sha256
raw_input_size_bytes
normalized_output_sha256
```

The raw digest binds the exact UTF-8 JSON bytes supplied to the command.

The normalized digest binds the canonical source declaration and normalized structured items.

For example, changing JSON indentation changes the raw digest but does not change the normalized output digest when the semantic content is unchanged.

The final `investigation_sha256` binds both raw and normalized lineage together with all upstream evidence digests.

## Resource bounds

The default response byte limit is:

```text
500000 bytes
```

The CLI exposes it as:

```text
--max-response-bytes
```

Additional deterministic limits apply to:

- items per kind;
- total item count;
- text length;
- declared provider/model length.

Oversized or malformed responses fail closed with an input error.

## What a hypothesis means

An investigation hypothesis is untrusted advisory reasoning.

Even if it references a deterministic finding, a `RELEASE_AUTHORITY` policy decision, or a high-confidence control result, the hypothesis itself remains:

```text
authority = INVESTIGATION_ADVISORY
gate_effect = NONE
```

The evidence reference means only:

> the investigator says this bounded hypothesis/observation/question was reasoned from these recorded nodes.

It does not mean Before Deploy has verified the hypothesis.

## Deterministic evidence remains deterministic

PR30 does not downgrade or rewrite deterministic evidence either.

The original graph node keeps its original authority. The investigation artifact merely references its stable node ID.

This produces a one-way trust boundary:

```text
deterministic evidence
        |
        | may be referenced by
        v
advisory investigation

advisory investigation
        X
        | may not rewrite/promote
        v
deterministic evidence or PolicyDecision
```

## Privacy boundary

PR30 receives only the PR29 inspection context, not the entire raw repository.

PR29 already avoids copying the legacy absolute repository path into its inspection artifact. PR30 preserves that boundary.

Raw provider payloads and raw source files are not embedded by the investigation layer. Existing evidence nodes may contain redaction-safe messages, locations, hashes, and provenance metadata because those are already part of the validated inspection trace.

## Deliberate exclusions

PR30 does not add:

- a live LLM/provider execution backend for investigation;
- internet research;
- semantic correlation outside the persisted inspection trace;
- confidence calibration;
- severity promotion;
- a provider-authored release verdict;
- mutation of `PolicyDecision`;
- remediation proposals;
- patch generation or application;
- verification;
- release disposition.

The provider-neutral request/response contract is intentional. Thin clients and future provider integrations can execute the reasoning step while this core remains responsible for bounding, validating, and attesting what entered and left that step.

## Next

PR31 adds `explain` on top of validated inspection and investigation artifacts. Explanation may improve developer comprehension, but it remains advisory and must cite the same stable evidence identities rather than manufacturing release authority.
