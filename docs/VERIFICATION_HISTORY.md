# Verification history and supersession

PR36 adds an immutable, gate-neutral history over PR35 verification artifacts.

The purpose of the history is to answer a narrow deterministic question:

> Which verification artifact is current for this inspected finding, and exactly which earlier verification did it supersede?

It does not answer whether the release is ready. Release disposition remains a later, separate deterministic decision.

## Authority boundary

Every history artifact is fixed to:

```text
authority = VERIFICATION_HISTORY
gate_effect = NONE
release_status = NOT_EVALUATED
resolution = APPEND_ORDER_EXPLICIT_SUPERSESSION_V1
```

History cannot mutate `PolicyDecision`, cannot upgrade advisory findings, and cannot claim `READY`, `HOLD`, `BLOCK`, or any other release disposition.

## Canonical verification input

`before-deploy history` consumes the persisted `verification.json` produced by PR35.

Before appending, Before Deploy reconstructs the typed verification artifact and validates:

- schema version;
- verification authority and gate neutrality;
- verification method;
- `release_status=NOT_EVALUATED`;
- content-addressed requirement IDs;
- content-addressed check IDs;
- one check per requirement;
- deterministic check-status mapping;
- deterministic overall status;
- `verification_sha256`;
- canonical JSON rendering, including authority-contract metadata.

PR36 does not rerun regression commands or recompute the PR34 materialization. It records the canonical verification evidence exactly as supplied.

## Entry model

Each history entry embeds the full canonical verification artifact and records:

```text
sequence
entry_sha256
verification_sha256
supersedes_verification_sha256
selected_node_id
patch_sha256
overall_status
evidence_identity_status
patch_review_status
materialization_review_status
verification
```

The entry digest binds all of those fields except its own digest slot.

The embedded verification preserves the exact PR35 requirements, checks, lineage hashes, and trust limitations.

## Linear supersession

History is intentionally linear in v1.

The root entry is:

```text
sequence = 1
supersedes_verification_sha256 = null
```

Every later entry must be:

```text
sequence = previous.sequence + 1
supersedes_verification_sha256 = previous.verification_sha256
```

The current entry is always the last valid appended entry.

There is no branching, status ranking, majority vote, provider preference, or confidence comparison in current resolution.

For example:

```text
verification A: PASS
        ↓ explicitly superseded by
verification B: FAIL
```

The current verification is B / `FAIL`.

The earlier PASS remains in history but is not current.

This is important because release logic must consume the latest explicit verification attempt, not cherry-pick the best historical result.

## Append-only invariants

A valid append requires:

1. the new verification artifact is canonical and internally valid;
2. the selected node ID matches the history selected node ID;
3. the verification SHA-256 does not already appear in history;
4. the new sequence is exactly one greater than the current sequence;
5. the new predecessor is exactly the current verification SHA-256;
6. all prior entries remain unchanged;
7. the resulting `history_sha256` validates.

Histories for different selected findings cannot be mixed.

## Trust preservation

History copies, but never upgrades:

```text
evidence_identity_status
patch_review_status
materialization_review_status
```

For example, a verification can be current and `PASS` while still recording:

```text
evidence_identity_status = DECLARED_UNATTESTED
patch_review_status = UNREVIEWED
materialization_review_status = UNREVIEWED
```

PR36 does not reinterpret those limitations.

## Content addressing

Each entry receives:

```text
entry_sha256 = SHA256(canonical entry payload)
```

The complete ledger receives:

```text
history_sha256 = SHA256(canonical history payload)
```

The history digest binds:

- selected node identity;
- current entry identity;
- current verification identity and status;
- resolution rule;
- release status;
- every ordered entry;
- every embedded canonical verification artifact;
- authority and gate neutrality.

No wall-clock timestamp is included in v1. Ordering is represented by explicit sequence and predecessor bindings, keeping the same append deterministic.

## CLI

Create a root history:

```text
before-deploy history reports/verify/verification.json
```

Append a later verification:

```text
before-deploy history reports/verify-later/verification.json \
  --history-file reports/history/verification-history.json
```

The command writes:

```text
verification-history.json
verification-history.md
```

A valid history exits 0 regardless of whether the current verification is `PASS`, `FAIL`, `ERROR`, or `INCOMPLETE`. Invalid/tampered input exits 2.

That behavior is deliberate: PR36 is evidence/history management, not release policy.

## Deliberate exclusions

PR36 does not add:

- release disposition;
- automatic policy mutation;
- verification status ranking;
- history branching or merge semantics;
- cryptographic signer identity;
- external runner attestation;
- human patch-review attestation;
- execution timestamps;
- deletion or replacement of prior history entries.

## Next boundary

PR37 can consume deterministic policy evidence plus the current verification selected by this ledger to produce an explicit release disposition.

That release step must continue to treat AI/advisory output as non-authoritative and must make evidence limitations visible rather than silently converting a verification PASS into a release approval.
