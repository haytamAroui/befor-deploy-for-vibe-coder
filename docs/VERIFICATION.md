# Deterministic Verification

PR35 adds a deterministic verification artifact over the exact PR33/PR34 remediation lineage.

Verification is not a second policy engine and is not a release disposition.

```text
RemediationProposal
  -> HumanApproval
  -> PatchArtifact
  -> PatchMaterializationAuthorization
  -> PatchMaterializationEvidence
  -> RegressionEvidence
  -> Verification
```

## Authority boundary

The verification artifact is always:

```text
authority = VERIFICATION_EVIDENCE
gate_effect = NONE
release_status = NOT_EVALUATED
```

`PolicyDecision` remains unchanged. PR35 does not produce `READY`, `HOLD`, `BLOCK`, or another release disposition.

A valid verification command exits successfully even when verification status is `FAIL`, `ERROR`, or `INCOMPLETE`. Invalid or tampered inputs are input errors. This prevents the CLI exit code from becoming an undocumented shadow release gate.

## Inputs

`before-deploy verify` reconstructs the existing review -> explanation -> proposal -> approval -> patch lineage and then consumes the persisted PR34 artifacts:

- `patch-materialization-authorization.json`;
- `patch-materialization.json`;
- `regression-evidence.json`.

It does not mutate the repository, reapply the patch, or rerun regression commands.

Each persisted PR34 artifact is reconstructed into its typed model, validated against upstream lineage, and compared to Before Deploy's canonical primitive representation. Tampering with semantic or display-only fields fails closed.

## Requirements

Every approved remediation verification goal becomes one deterministic requirement:

```text
verification_goal_id
kind
statement
required_observation_status = PASS
```

Each requirement receives exactly one check bound to the exact content-addressed regression observation for that goal.

Observation status maps deterministically:

| Regression observation | Verification check |
| --- | --- |
| `PASS` | `SATISFIED` |
| `FAIL` | `FAILED` |
| `ERROR` | `ERROR` |
| `NOT_RUN` | `INCOMPLETE` |

The aggregate verification status uses the precedence:

```text
ERROR > FAIL > INCOMPLETE > PASS
```

No model confidence, severity, explanatory prose, or provider preference participates in this evaluation.

## What PASS means

A PR35 `PASS` means:

- the exact approved patch lineage is valid;
- materialization evidence records `APPLIED_HASH_VERIFIED` for that patch;
- every declared remediation verification goal has exactly one bound regression observation;
- every such observation records `PASS`;
- the verification artifact and all requirement/check IDs are content-addressed and internally valid.

It does **not** mean:

- an external runner identity is cryptographically attested;
- the generated patch bytes were human-reviewed;
- no defect remains;
- the original deterministic `PolicyDecision` changed;
- the release is ready.

## Evidence trust is preserved

PR34 regression evidence currently records external runner identity as:

```text
identity_status = DECLARED_UNATTESTED
```

PR35 copies that fact into:

```text
evidence_identity_status = DECLARED_UNATTESTED
```

Verification never upgrades it to `ATTESTED` merely because all observations say `PASS`.

Likewise, PR33/PR34 patch review remains:

```text
patch_review_status = UNREVIEWED
materialization_review_status = UNREVIEWED
```

A deterministic verification result cannot rewrite either field.

## Content-addressed verification

Each requirement is assigned:

```text
verification-requirement:<sha256>
```

from its exact goal ID, kind, statement, and required status.

Each check is assigned:

```text
verification-check:<sha256>
```

from its exact requirement, regression observation, observed status, and derived check status.

The final artifact binds:

```text
proposal_sha256
approval_sha256
patch_request_sha256
patch_sha256
materialization_authorization_sha256
materialization_sha256
regression_request_sha256
regression_evidence_sha256
requirements
checks
overall_status
release_status
        ↓
verification_sha256
```

Timing and host-specific workspace paths are not part of the verification digest.

## CLI

```text
before-deploy verify <review.json> <selector> \
  --explanation-response-file explanation-response.json \
  --proposal-response-file proposal-response.json \
  --approval-file human-approval.json \
  --patch-response-file patch-response.json \
  --materialization-authorization-file patch-materialization-authorization.json \
  --materialization-file patch-materialization.json \
  --regression-evidence-file regression-evidence.json
```

If the earlier explanation used investigation context, pass the same `--investigation-response-file` used by the upstream workflow.

The command writes:

```text
verification.json
verification.md
```

## Failure semantics

A valid artifact can have one of four statuses:

```text
PASS
FAIL
ERROR
INCOMPLETE
```

These are evidence-evaluation outcomes, not release outcomes.

Examples:

- test observation `FAIL` -> verification `FAIL`;
- runner/tool observation `ERROR` -> verification `ERROR`;
- declared verification goal with `NOT_RUN` -> verification `INCOMPLETE`;
- every goal `PASS` -> verification `PASS`.

A malformed digest, wrong lineage binding, unsupported authority field, noncanonical persisted artifact, missing goal, duplicate goal, or forged release status is rejected as invalid input instead of becoming a verification result.

## Deferred to later PRs

PR35 deliberately does not add:

- verification history / supersession (`PR36`);
- release disposition (`PR37`);
- automatic LLM judgment;
- automatic release-policy mutation;
- external runner attestation;
- human patch-review attestation.

PR36 can now build immutable verification history over `verification_sha256`, and PR37 can consume deterministic policy plus the verification/history evidence to produce an explicit release disposition.