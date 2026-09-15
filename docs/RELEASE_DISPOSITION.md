# Deterministic release disposition

PR37 adds the final deterministic `before-deploy release` authority layer.

The release command does not invoke an LLM, advisory provider, explanation workflow, or semantic reviewer. It consumes only:

1. a persisted deterministic `report.json` from `before-deploy scan`;
2. a canonical PR36 `verification-history.json`;
3. the exact PR34 `patch-materialization.json` referenced by the current verification;
4. the current repository workspace.

The release artifact is content-addressed and records:

```text
policy report -> PolicyReleaseEvidence
verification history -> current Verification
patch materialization -> exact post-patch file hashes
current workspace -> repository digest + target hashes
                         |
                         v
                  ReleaseDisposition
```

## Authority model

The deterministic `PolicyDecision` remains the sole security-policy authority. PR37 adds a final deterministic release authority that may make a passing security-policy decision more restrictive when required workflow/snapshot evidence is missing or failing; it can never soften a negative policy decision.

```text
PolicyDecision ERROR             -> Release ERROR
PolicyDecision BLOCK             -> Release BLOCK
PolicyDecision WAIVER_REQUIRED   -> Release HOLD
PolicyDecision NOT_EVALUATED     -> Release HOLD
PolicyDecision PASS              -> evaluate release evidence
```

Only when policy is `PASS` are the current workspace and current verification considered.

```text
workspace drift                  -> HOLD
materialized target drift        -> HOLD
verification ERROR               -> ERROR
verification FAIL                -> BLOCK
verification INCOMPLETE          -> HOLD
verification PASS                -> evaluate declared trust requirements
all declared requirements met    -> READY
```

A passing verification can never override `BLOCK`, `ERROR`, `WAIVER_REQUIRED`, or `NOT_EVALUATED` from deterministic policy.

## Workspace binding

A final release decision must describe the current release contents, not a stale collection of artifacts.

`release` therefore rebuilds the normal bounded repository inventory and recomputes its repository SHA-256 using the same inventory/digest functions used by `scan`.

The observed digest must equal the persisted scan manifest `repository_digest` before `READY` is possible.

PR37 also loads the exact PR34 patch materialization referenced by the current verification history entry. Every materialized target must:

- be a canonical repository-relative POSIX path;
- remain inside the repository root;
- contain no symlink component;
- be a regular file;
- remain inside the deterministic scan inventory;
- still have the recorded post-materialization SHA-256.

Repository or target drift is evidence staleness, not malformed input, so it produces `HOLD`.

## Verification history

PR37 always uses the current verification resolved by PR36's append-order supersession rule.

It never searches history for a more favorable prior result. A later `FAIL` superseding an earlier `PASS` therefore remains the current verification and blocks release under an otherwise passing policy.

## Trust requirements

PR35/36 preserve trust limitations instead of upgrading them. Current PR34 evidence records:

```text
evidence_identity_status = DECLARED_UNATTESTED
patch_review_status = UNREVIEWED
materialization_review_status = UNREVIEWED
```

Those states are always surfaced in `ReleaseDisposition.limitations`.

PR37 does not silently convert them into stronger claims. The default release contract does not require these stronger attestations, because the current roadmap has not yet introduced canonical artifacts that can satisfy them.

A caller can deterministically require them:

```text
--require-attested-evidence
--require-reviewed-patch
--require-reviewed-materialization
```

When a requested requirement is not satisfied, disposition is `HOLD`.

The exact requirement booleans are content-addressed through `requirements_sha256` and included in `disposition_sha256`.

## Advisory boundary

Provider/LLM output is structurally excluded from the release decision function.

PR37 does not load advisory provider execution, confidence, severity, correlation, corroboration, investigation, explanation, or proposal content to decide release status.

The remediation lineage can reach release only after explicit human approval, exact patch materialization, regression evidence, deterministic verification, and immutable history. The final decision depends on those deterministic workflow artifacts and current workspace state—not on an LLM saying a finding is severe or a release is safe.

## CLI

```bash
before-deploy release reports/report.json \
  --verification-history-file reports/history/verification-history.json \
  --materialization-file reports/regress/patch-materialization.json \
  --repository .
```

Optional stricter evidence requirements:

```bash
before-deploy release reports/report.json \
  --verification-history-file reports/history/verification-history.json \
  --materialization-file reports/regress/patch-materialization.json \
  --repository . \
  --require-attested-evidence \
  --require-reviewed-patch
```

Outputs:

```text
reports/release/release-disposition.json
reports/release/release-disposition.md
```

Exit contract:

```text
0  READY
1  HOLD or BLOCK
2  authoritative release ERROR
3  malformed/tampered/incompatible input
```

Unlike `verify` and `history`, `release` is intentionally a deploy gate, so a valid non-ready disposition returns non-zero.

## Release artifact

The canonical artifact includes:

- `status`: `READY | HOLD | BLOCK | ERROR`;
- contextual `gate_effect`: `ALLOW | HOLD | BLOCK | ERROR`;
- policy report/evidence digests;
- repository and policy digests;
- verification-history/current-verification digests;
- exact patch/materialization digests;
- release requirement flags and digest;
- current workspace assessment;
- preserved evidence/review trust status;
- deterministic reason codes;
- explicit assurance limitations;
- `disposition_sha256`;
- `authority = RELEASE_DISPOSITION`.

`disposition_sha256` is an integrity/reproducibility identifier over the canonical release facts. It is not a cryptographic signature or proof of artifact authenticity.

## Meaning of READY

`READY` means, within the declared PR37 contract:

- the persisted deterministic security policy decision is `PASS`;
- the current workspace still matches the policy scan repository digest;
- every materialized patch target remains in scan scope and matches its recorded result hash;
- the current verification selected by immutable history is `PASS`;
- all explicitly configured PR37 trust requirements are satisfied.

It does **not** prove absence of all vulnerabilities, defects, or uncovered assurance gaps. It does not attest evidence sources unless an attested identity is actually present, and it does not imply patch review unless reviewed status is actually present.
