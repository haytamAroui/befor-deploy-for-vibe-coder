# Before Deploy Agent Runtime v1

PR41 introduces the native iterative AI execution kernel for the discovery/reasoning plane. It does not connect a vendor API, add a release gate, approve remediation, mutate a workspace, or reinterpret deterministic policy.

## Authority boundary

Every run and every retained claim is fixed to:

```text
authority = AI_DISCOVERY_ADVISORY
gate_effect = NONE
release_status = NOT_EVALUATED
```

The model response schema has no field for a waiver, approval, verification result, `PolicyDecision`, release status, or release gate effect. An invalid provider turn becomes an advisory run error; it never falls through into deterministic authority.

## Bounded loop

```text
deterministic starting context
          |
          v
      model turn
       /      \
 TOOL          FINAL
  |              |
  v              v
deterministic   cited advisory
mediator        claims only
  |
  +--> hashed bounded evidence
          |
          `------> next model turn
```

The runtime enforces hard positive limits for:

- model steps;
- tool calls;
- bytes returned by each tool;
- aggregate provider-reported input tokens;
- aggregate provider-reported output tokens;
- aggregate provider-reported micro-USD cost;
- wall-clock duration.

A budget overrun ends the run as `BUDGET_EXHAUSTED` and retains no final claims.

## Evidence binding

Starting context items carry a content SHA-256. Tool results carry a content SHA-256 and receive a content-addressed `agent-tool:<sha256>` evidence ID.

A final claim must cite at least one evidence ID, and every cited ID must be either:

1. a validated starting-context evidence ID, or
2. a tool-result evidence ID produced in the same run.

Claims that cite unseen or invented evidence fail the run rather than entering the advisory plane.

## Claim normalization

Before Deploy, not the model, assigns the canonical claim ID. The ID binds the normalized title, message, category, severity, confidence, evidence references, optional repository-relative location, and declared assumptions.

Paths must be canonical repository-relative paths. Parent traversal, absolute paths, drive paths, invalid line ranges, unknown categories, and unknown severities are rejected.

## Run provenance

A run records:

- specialist role;
- provider/model identity declared by the adapter;
- objective;
- budget and aggregate usage;
- step/tool-call counts;
- duration;
- deterministic starting-context digest;
- ordered tool-result content digests;
- normalized retained claims;
- completion/error state;
- content-addressed `run_sha256`.

The runtime does not request or persist private chain-of-thought. Model adapters return structured actions plus an optional bounded summary suitable for the next turn.

## Next slices

PR42 adds deterministic repository tools, path/tool authorization, symbol/reference/call/dependency lookup, and bounded repository search.

PR43 adds specialist orchestration, critic/reflection, exact claim correlation, and advisory corroboration metadata.

PR44 adds native model adapters and routing. Only after those layers are independently bounded will the native agent be exposed through `before-deploy review`.
