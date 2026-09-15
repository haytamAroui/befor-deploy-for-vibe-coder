# Evidence Explanation

## Purpose

PR31 adds an advisory explanation layer on top of the validated evidence stack.

The ordering is intentional:

```text
review.json
  -> Evidence Graph
  -> correlation / corroboration
  -> inspect
  -> investigate (optional)
  -> explain
```

`explain` is a presentation and interpretation layer. It is not a new detector, evidence source, policy evaluator, remediation engine, or release authority.

## Command

Build explanation context from a persisted review artifact:

```bash
before-deploy explain reports/review.json <selector>
```

Optionally include a bounded PR30 investigation response:

```bash
before-deploy explain reports/review.json <selector> \
  --investigation-response-file investigation-response.json
```

Import a strict explanation response:

```bash
before-deploy explain reports/review.json <selector> \
  --investigation-response-file investigation-response.json \
  --response-file explanation-response.json
```

Without `--response-file`, the command writes only:

- `explanation-request.json`
- `explanation-request.md`

With `--response-file`, it additionally writes:

- `explanation.json`
- `explanation.md`

The command does not rerun the deterministic scan or release policy.

## Authority contract

Explanation context is explicitly gate-neutral:

```text
authority = EXPLANATION_CONTEXT
gate_effect = NONE
```

Imported explanation output is also gate-neutral:

```text
authority = EXPLANATION_ADVISORY
gate_effect = NONE
```

Only the persisted deterministic `PolicyDecision` remains release authority.

An explanation cannot:

- change `PASS`, `BLOCK`, `WAIVER_REQUIRED`, or `ERROR`;
- promote an advisory finding to deterministic authority;
- modify severity or provider confidence;
- modify correlation or corroboration state;
- create new deterministic evidence;
- create a remediation proposal or patch.

Remediation is deliberately deferred to PR32+.

## Citation boundary

Every explanation statement must cite at least one source already present in the request.

Two citation namespaces are allowed:

1. Evidence Graph node IDs already included in the PR29 inspection trace.
2. Content-addressed PR30 investigation item IDs supplied in the optional investigation context.

The explainer cannot cite arbitrary repository paths, unseen graph nodes, external URLs, or invented evidence IDs.

This applies to all three explanation sections:

- summary;
- details;
- limitations.

Even the summary cannot be free-floating prose.

## Strict response schema

A response uses schema version 1:

```json
{
  "schema_version": 1,
  "request_sha256": "...",
  "source": {
    "provider": "example-explainer",
    "model": "optional-declared-model"
  },
  "summary": {
    "text": "...",
    "evidence_node_ids": ["..."],
    "investigation_item_ids": []
  },
  "details": [
    {
      "text": "...",
      "evidence_node_ids": ["..."],
      "investigation_item_ids": ["..."]
    }
  ],
  "limitations": [
    {
      "text": "...",
      "evidence_node_ids": ["..."],
      "investigation_item_ids": []
    }
  ]
}
```

Unknown fields fail closed.

For example, provider-authored fields such as these are rejected:

```text
release_decision
policy_decision
authority
gate_effect
severity
confidence
statement_id
remediation
patch
```

The response cannot create a shadow policy or shadow remediation model.

## Content-addressed statements

Provider-supplied statement IDs are not accepted.

Before Deploy assigns IDs after normalization:

```text
explanation-summary:<sha256>
explanation-detail:<sha256>
explanation-limitation:<sha256>
```

The digest binds:

- normalized text;
- sorted evidence-node citations;
- sorted investigation-item citations.

Exact duplicates therefore normalize to the same identity.

## Upstream binding

The request is bound to the full evidence lineage through:

```text
source_review_sha256
graph_sha256
correlation_sha256
corroboration_sha256
inspection_sha256
investigation_request_sha256
investigation_sha256 (optional)
request_sha256
```

If no investigation result is supplied, `investigation_sha256` is null and the allowed investigation-item set is empty.

If investigation context is supplied, it is first validated against its PR30 investigation request before becoming explanation context.

## Raw to normalized provenance

Imported explanation output records:

```text
raw_input_sha256
raw_input_size_bytes
normalized_output_sha256
explanation_sha256
```

`raw_input_sha256` identifies the exact response bytes.

`normalized_output_sha256` identifies the canonical accepted semantic content. JSON formatting differences can therefore change the raw digest without changing the normalized digest.

`explanation_sha256` binds normalized output to its exact upstream explanation request and evidence lineage.

Raw provider output is not embedded as a separate payload in the canonical explanation artifact.

## Identity honesty

A JSON response may declare a provider and model, but the file itself does not prove who generated it.

PR31 therefore records:

```text
identity_status = DECLARED_UNATTESTED
```

A later live-provider client may supply stronger execution attestation through an explicit provider runtime. PR31 does not infer or fabricate that attestation.

## Resource bounds

Explanation response import is bounded by:

- maximum response bytes;
- maximum detail count;
- maximum limitation count;
- maximum total item count;
- maximum statement text length;
- maximum declared identity length.

Malformed, oversized, uncited, or out-of-context responses fail as diagnostic input errors. They do not affect the deterministic gate.

## Privacy boundary

The explanation request reuses the redaction-safe PR29 inspection representation and normalized PR30 investigation content.

It does not add arbitrary repository reads, raw source-code transport, or unrelated absolute repository paths.

## Deliberate exclusions

PR31 does not add:

- live LLM execution;
- web research;
- new evidence discovery;
- semantic correlation changes;
- confidence calibration;
- remediation proposals;
- patch generation;
- human approval;
- regression evidence;
- verification;
- release disposition.

The next increment is PR32: a separate remediation-proposal model that remains non-executable until later human approval and patch stages.
