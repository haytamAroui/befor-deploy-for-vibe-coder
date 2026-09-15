# Regression evidence

PR34 adds the first controlled workspace mutation in the remediation lineage. It remains outside release authority.

## Lineage

```text
RemediationProposal
  -> HumanApproval (proposal approval)
  -> PatchArtifact (NOT_APPLIED / UNREVIEWED)
  -> PatchMaterializationAuthorization (exact patch confirmation)
  -> PatchMaterialization (APPLIED_HASH_VERIFIED / UNREVIEWED)
  -> RegressionEvidenceRequest
  -> RegressionEvidence
```

The second confirmation is intentional. PR33 human approval authorizes patch generation for one proposal; it does not authorize applying arbitrary generated diff bytes. PR34 therefore requires the operator to confirm the exact `patch_sha256` before any workspace mutation.

## CLI

```text
before-deploy regress <review.json> <selector> \
  --explanation-response-file explanation-response.json \
  --proposal-response-file proposal-response.json \
  --approval-file human-approval.json \
  --patch-response-file patch-response.json \
  --repository /path/to/workspace \
  --confirm-patch-sha256 <patch_sha256> \
  --operator <declared-human-identity>
```

If the explanation used investigation context, pass the same `--investigation-response-file` used upstream.

The command materializes the exact patch and writes:

```text
patch-materialization-authorization.json
patch-materialization-authorization.md
patch-materialization.json
patch-materialization.md
regression-evidence-request.json
regression-evidence-request.md
```

With `--regression-response-file before-deploy-regression-evidence-v1.json`, it additionally writes:

```text
regression-evidence.json
regression-evidence.md
```

## Materialization safety contract

Before any write, PR34 validates all patch targets and derives all result bytes in memory.

For every target:

1. path must be an existing canonical repository-relative path from the approved patch;
2. the repository root and every target component must not be a symlink;
3. the target must be an existing regular file;
4. target bytes must be UTF-8 text;
5. the observed pre-write SHA-256 must equal `base_content_sha256`;
6. the strict unified diff must apply to the observed text;
7. the derived result SHA-256 must equal `patched_content_sha256`.

Only after **every** target passes preflight are replacement files staged. Writes use same-directory temporary files and `os.replace`. If a replacement or post-write hash check fails, Before Deploy restores the original bytes for targets it changed.

Patch materialization v1 deliberately rejects CRLF targets, zero-line hunks, no-newline markers, symlinked targets, file creation/deletion, and binary patches. Those limitations are explicit rather than silently widening the patch engine.

## Materialization authority

Exact-patch confirmation is recorded as:

```text
authority = PATCH_MATERIALIZATION_WORKFLOW
gate_effect = NONE
identity_status = DECLARED_UNATTESTED
scope = APPLY_EXACT_PATCH_FOR_REGRESSION_ONLY
```

The resulting observed mutation is:

```text
authority = PATCH_MATERIALIZATION_EVIDENCE
gate_effect = NONE
application_status = APPLIED_HASH_VERIFIED
review_status = UNREVIEWED
```

Applying the patch does **not** imply that a human reviewed the generated diff and does not authorize release.

The persisted materialization artifact contains repository-relative target paths and pre/post content hashes only. It does not persist the absolute workspace path.

## Regression evidence request

The request is derived from the exact patch materialization and the remediation proposal's verification goals. Every approved verification goal must receive exactly one observation.

```text
authority = REGRESSION_EVIDENCE_CONTEXT
gate_effect = NONE
```

PR34 does not execute arbitrary verification commands. Test/static/manual execution happens in an external runner or human workflow. This keeps the Before Deploy core from turning advisory/remediation content into a command-execution channel.

## Imported regression observations

The strict response format is:

```json
{
  "schema_version": 1,
  "request_sha256": "...",
  "source": {
    "runner": "external-ci",
    "environment": "linux-py311"
  },
  "observations": [
    {
      "verification_goal_id": "remediation-verification:...",
      "kind": "TEST",
      "status": "PASS",
      "command": ["pytest", "tests/test_regression.py"],
      "exit_code": 0,
      "duration_ms": 315,
      "stdout_sha256": "...",
      "stderr_sha256": "...",
      "statement": "Targeted regression test passed."
    }
  ]
}
```

Raw stdout/stderr is not accepted into the canonical artifact. Only optional SHA-256 digests are retained.

Provider/runner-supplied observation IDs and aggregate status are not accepted. Before Deploy content-addresses observations and derives aggregate status with deterministic precedence:

```text
ERROR > FAIL > INCOMPLETE > PASS
```

`NOT_RUN` yields aggregate `INCOMPLETE` unless a stronger failure/error status is present.

The imported runner identity remains:

```text
identity_status = DECLARED_UNATTESTED
```

because a JSON file cannot prove who or what actually executed the checks.

## Regression evidence authority

```text
authority = REGRESSION_EVIDENCE
gate_effect = NONE
```

Regression evidence is input to later verification. It cannot change `PolicyDecision`, upgrade an advisory finding, authorize release, or claim that a release is safe.

## Privacy and provenance

The regression artifact binds:

```text
patch_request_sha256
patch_sha256
materialization_authorization_sha256
materialization_sha256
regression_request_sha256
raw_input_sha256
normalized_output_sha256
regression_evidence_sha256
```

It persists no absolute repository path and no raw source file contents.

## Deliberate exclusions

PR34 does not:

- execute test commands itself;
- attest the external runner identity;
- imply human review of patch bytes;
- create release authority;
- change deterministic `PolicyDecision`;
- decide whether regression evidence is sufficient for release.

PR35 (`verify`) will evaluate the exact patch/materialization/regression lineage against deterministic verification requirements without asking an LLM whether the release is safe.
