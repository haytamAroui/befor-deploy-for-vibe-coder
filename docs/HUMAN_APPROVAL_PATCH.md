# Human Approval and Patch Artifacts

PR33 adds an explicit authorization boundary between a remediation proposal and patch content.

The intended trace is:

```text
RemediationProposal
  proposal_sha256
       |
       v
HumanApproval
  approval_sha256
       |
       v
PatchRequest
  request_sha256
       |
       v
PatchArtifact
  patch_sha256
```

None of these artifacts changes the persisted deterministic `PolicyDecision`.

## Human approval is not release authority

`before-deploy approve` requires the operator to provide the exact proposal digest again:

```text
--confirm-proposal-sha256 <proposal_sha256>
```

The resulting artifact records:

```text
authority = HUMAN_APPROVAL_WORKFLOW
gate_effect = NONE
decision = APPROVE | REJECT
identity_status = DECLARED_UNATTESTED
```

The CLI cannot cryptographically prove who is at the keyboard, so the approver identity is explicitly declared and unattested. This artifact records an explicit workflow action; it must not be presented as cryptographic human identity proof.

`APPROVE` means only:

> patch generation is authorized for this exact remediation proposal.

It does **not** mean:

- the generated patch has been reviewed;
- the patch may be applied to production;
- regression evidence exists;
- verification passed;
- release is approved;
- deterministic policy changed.

`REJECT` is retained as workflow evidence and cannot unlock a patch request.

## Patch request scope

A patch request is derived only after validating:

```text
review.json
 -> inspection
 -> optional investigation
 -> explanation
 -> remediation proposal
 -> human approval (APPROVE)
```

The request derives its allowed target paths from the approved proposal. Patch response paths cannot widen that set.

The request remains:

```text
authority = PATCH_CONTEXT
gate_effect = NONE
```

## Patch artifact v1

PR33 imports patch content through a strict structured response. Each file contains:

```text
target_path
base_content_sha256
patched_content_sha256
unified_diff
```

Before Deploy assigns:

```text
patch-file:<sha256>
```

and binds the complete normalized patch with:

```text
patch_sha256
```

The patch result is always:

```text
authority = PATCH_ARTIFACT
gate_effect = NONE
application_status = NOT_APPLIED
review_status = UNREVIEWED
```

The approval applies to the **proposal**, not to the generated diff. Therefore patch generation must never silently upgrade `review_status`.

## Patch scope rules

Patch v1 intentionally supports only text modifications to already-present paths described by the proposal.

It rejects:

- extra paths;
- omitted approved target paths;
- duplicate target paths;
- file creation/deletion headers;
- binary patches;
- diff headers that name a different path;
- patches without hunks or changed lines;
- equal base/result content digests;
- provider-authored release, gate, approval, application, or review status fields.

Every target from the approved proposal must appear exactly once.

## Content digest semantics

`base_content_sha256` and `patched_content_sha256` are declarations carried by the patch artifact. PR33 does not read or mutate repository bytes to prove them.

A later application/regression stage must verify the base digest before applying the patch and verify the result digest after materialization. This prevents a generated patch from being treated as if it had already been applied or verified.

## CLI

Create explicit approval/rejection:

```text
before-deploy approve review.json <selector> \
  --explanation-response-file explanation-response.json \
  --proposal-response-file proposal-response.json \
  --decision APPROVE \
  --approver alice@example.test \
  --confirm-proposal-sha256 <proposal_sha256>
```

This writes:

```text
human-approval.json
human-approval.md
```

Create a patch-generation request:

```text
before-deploy fix review.json <selector> \
  --explanation-response-file explanation-response.json \
  --proposal-response-file proposal-response.json \
  --approval-file human-approval.json
```

This writes:

```text
patch-request.json
patch-request.md
```

With a structured patch response:

```text
--patch-response-file patch-response.json
```

it additionally writes:

```text
patch.json
patch.md
```

No command in PR33 applies the patch to the repository.

## Authority invariant

```text
RemediationProposal
  REMEDIATION_PROPOSAL_ADVISORY
  gate_effect=NONE

HumanApproval
  HUMAN_APPROVAL_WORKFLOW
  gate_effect=NONE

PatchArtifact
  PATCH_ARTIFACT
  gate_effect=NONE
  NOT_APPLIED
  UNREVIEWED

PolicyDecision
  RELEASE_AUTHORITY
```

Human approval is an authorization step in the remediation workflow, not a replacement for deterministic release policy.

## Next

PR34 should create regression evidence bound to the exact `patch_sha256`. If it materializes a patch in a controlled workspace, it must verify the declared base-content digests before mutation and resulting-content digests afterward, then record test/scan evidence without changing release authority directly.
