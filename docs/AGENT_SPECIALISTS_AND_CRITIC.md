# Specialist agents and critic reflection

PR43 adds multi-specialist reasoning above the bounded PR41 runtime and PR42 repository tools. It deliberately treats agreement and criticism as advisory evidence interpretation, never as release authority.

## Specialist catalog

The catalog includes broad reviewers for general correctness, concurrency, API contracts, cross-file data flow, tests, and security, plus focused security roles for authorization, authentication, injection, SSRF, secrets, cryptography, sessions, deserialization, file upload, path traversal, business logic, supply chain, and cloud/IaC.

The default set remains bounded to seven broad reviewers. Later coverage planning can select focused specialists only where project profile, deterministic findings, or coverage gaps justify them.

## Exact-claim corroboration

Before Deploy groups only exact normalized claim semantics. The grouping identity excludes provider/model identity, confidence, and evidence provenance so independently produced identical claims can be recognized without pretending differently worded findings are semantically equivalent.

Corroboration states are qualitative:

```text
SINGLE
REPEATED_EXACT_CLAIM
MULTI_EXECUTION_EXACT_CLAIM
MULTI_SPECIALIST_EXACT_CLAIM
```

Provider/model/specialist diversity is retained as provenance facts. There is no numeric confidence promotion, severity promotion, policy mutation, or voting gate.

## Critic pass

Every unique candidate claim receives a critic run. The critic sees the original bounded context plus the candidate represented as a content-hashed context item and may use the same deterministic repository tools.

The result is one of:

```text
RETAIN
REVISE
REJECT
UNREVIEWED
```

A retained or revised critic claim must cite evidence beyond the candidate itself. A critic that merely cites the candidate is rejected. A critic runtime failure or ambiguous result becomes `UNREVIEWED`; it does not erase the original advisory candidate and cannot alter deterministic release state.

No private chain-of-thought is persisted. The orchestration artifact records normalized claims, run identities, qualitative corroboration, critic decisions, bounded notes, and a content-addressed orchestration digest.

## Authority invariant

```text
authority = AI_ORCHESTRATION_ADVISORY
gate_effect = NONE
release_status = NOT_EVALUATED
```

Three agents agreeing does not mean `BLOCK`. A critic retaining a claim does not mean `BLOCK`. These signals improve investigation priority and evidence quality only.
