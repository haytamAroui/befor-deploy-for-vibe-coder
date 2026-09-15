# Remediation Proposal

PR32 adds a bounded, evidence-cited remediation proposal artifact. It is intentionally separate from patch generation and release authority.

## Purpose

The workflow turns a validated PR31 explanation into a structured plan describing:

- the remediation objective;
- intended repository-relative target paths;
- the intent of each proposed change;
- verification goals;
- bounded risk statements.

The proposal is planning metadata. It does not modify files, create a diff, execute commands, approve itself, or change `PolicyDecision`.

## CLI

Build proposal context from an existing review and a validated explanation response:

```text
before-deploy propose reports/review.json <selector> \
  --explanation-response-file explanation-response.json
```

If the explanation was built with PR30 investigation context, provide the same investigation response:

```text
before-deploy propose reports/review.json <selector> \
  --investigation-response-file investigation-response.json \
  --explanation-response-file explanation-response.json
```

Without `--response-file`, the command writes:

```text
remediation-proposal-request.json
remediation-proposal-request.md
```

With a strict proposal response:

```text
--response-file remediation-proposal-response.json
```

it additionally writes:

```text
remediation-proposal.json
remediation-proposal.md
```

## Upstream validation

`propose` rebuilds and validates the complete upstream chain before creating proposal context:

```text
review.json
  -> Evidence Graph / correlation / corroboration validation
  -> inspection
  -> investigation request
  -> optional investigation response validation
  -> explanation request
  -> explanation response validation
  -> remediation proposal request
```

A proposal therefore binds:

```text
source_review_sha256
graph_sha256
correlation_sha256
corroboration_sha256
inspection_sha256
investigation_request_sha256
investigation_sha256 (optional)
explanation_request_sha256
explanation_sha256
request_sha256
```

The imported proposal additionally records:

```text
raw_input_sha256
raw_input_size_bytes
normalized_output_sha256
proposal_sha256
```

## Authority boundary

The request is always:

```text
authority = REMEDIATION_CONTEXT
gate_effect = NONE
```

The result is always:

```text
authority = REMEDIATION_PROPOSAL_ADVISORY
gate_effect = NONE
execution_status = NON_EXECUTABLE
approval_status = NOT_APPROVED
```

These fields are assigned and validated by Before Deploy. They are not accepted from an external proposer.

`PolicyDecision` remains the only release authority.

## Strict response schema

The response may contain only:

```text
schema_version
request_sha256
source
objective
changes
verification_goals
risks
```

The source contains only a declared provider and optional declared model. That identity remains:

```text
DECLARED_UNATTESTED
```

An arbitrary JSON file does not prove which provider or model produced it.

### Objective

The objective contains prose plus bounded citations.

### Changes

Each change contains:

```text
target_path
intent
rationale (optional)
evidence_node_ids (optional)
investigation_item_ids (optional)
explanation_statement_ids (optional)
```

At least one citation is required.

`target_path` is a canonical repository-relative POSIX path. Absolute paths, parent traversal, backslashes, and non-canonical path spellings are rejected.

A target path describes intended scope only. It grants no filesystem access and triggers no repository read or write.

### Verification goals

Each verification goal uses one of:

```text
TEST
STATIC_SCAN
RUNTIME_CHECK
MANUAL_REVIEW
OTHER
```

and must include a cited statement. These are desired checks, not executed checks and not regression evidence.

### Risks

Risk statements are optional but, when present, must also cite bounded upstream context.

## Structural non-executability

The canonical response schema has no fields for:

- patch or diff content;
- replacement source;
- commands;
- executable scripts;
- approval;
- release decisions;
- gate effects;
- severity/confidence changes.

Unknown fields fail closed rather than being ignored.

Free-form intent/rationale text is prose; Before Deploy does not claim lexical analysis can prove prose never resembles source code. The enforceable boundary is that PR32 exposes no execution or patch application mechanism and no canonical executable patch representation.

## Content-addressed identities

Before Deploy assigns normalized IDs after validation:

```text
remediation-objective:<sha256>
remediation-change:<sha256>
remediation-verification:<sha256>
remediation-risk:<sha256>
```

The proposer cannot supply these IDs.

Exact duplicate normalized items collapse deterministically through their content identity.

## Citations

Every semantic item must cite at least one allow-listed identifier from the validated upstream context:

```text
Evidence Graph node ID
Investigation item ID
Explanation statement ID
```

References outside those allow-lists fail closed.

The proposal can therefore describe an intended change without pretending the proposal itself is new evidence.

## Human approval and PR33

PR32 deliberately cannot produce an approved proposal.

The next patch stage must introduce or consume a separate human approval artifact that identifies the exact:

```text
proposal_sha256
```

A patch must not be generated or applied merely because a proposal exists.

The intended transition is:

```text
RemediationProposal
  -> HumanApproval
  -> Patch
```

not:

```text
RemediationProposal -> Patch
```

This preserves the boundary between advisory planning and authorized mutation.
