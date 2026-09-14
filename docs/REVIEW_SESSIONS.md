# Review Sessions and Longitudinal Delta

## Purpose

`before-deploy review` now writes a compact `review-session.json` snapshot that can be used as an explicit baseline for a later review.

The goal is to make repeated reviews useful without pretending that a missing AI finding proves a bug was fixed.

## Usage

First review:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --ocr \
  --output-dir reports/current
```

This writes:

```text
reports/current/review-session.json
```

Later review:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --ocr \
  --baseline-session reports/current/review-session.json \
  --output-dir reports/next
```

The second run additionally writes:

```text
reports/next/review-delta.json
reports/next/review-delta.md
```

A baseline may also point to the previous `review-session.json` in the same output directory. Before Deploy loads the baseline before overwriting the current session artifact.

## Lifecycle states

The comparison is fingerprint-based and deliberately uses conservative terminology:

| State | Meaning |
|---|---|
| `NEW` | The current run reports a fingerprint that the baseline did not contain. |
| `PERSISTING` | The same fingerprint exists in both runs. |
| `ABSENT_CURRENT` | The baseline fingerprint is not reported in the current run. This does **not** prove remediation. |

Before Deploy intentionally does not label `ABSENT_CURRENT` as `FIXED` or `RESOLVED`.

A finding may disappear because:

- the code was fixed;
- OCR/model behavior changed;
- advisory scope became partial;
- the provider failed;
- a deterministic control became non-applicable;
- the policy/control set changed;
- the relevant source location or evidence changed enough to produce a new fingerprint.

Human or stronger deterministic verification is required before treating absence as remediation evidence.

## Two planes remain separate

The delta keeps deterministic and advisory findings separate:

```text
Deterministic
  NEW
  PERSISTING
  ABSENT_CURRENT

Advisory
  NEW
  PERSISTING
  ABSENT_CURRENT
```

An advisory finding never becomes deterministic because it persisted across runs.

Likewise, lifecycle comparison never changes:

- `PolicyDecision`;
- `PASS` / `BLOCK` / `WAIVER_REQUIRED` / `ERROR`;
- waivers;
- policy;
- control health;
- release authority.

## Advisory coverage context

Each review session stores only minimal advisory-source health:

```text
source
status
scope_status
```

If either the current or baseline advisory source is incomplete—for example `PARTIAL`, `PREFLIGHT_ONLY`, `ERROR`, `DRIFT`, or `EXPANDED`—the delta includes a warning that `ABSENT_CURRENT` requires human interpretation.

This prevents a narrower or failed AI review from looking like successful remediation.

## Repository identity

Before Deploy refuses to compare sessions when their repository identities differ.

For Git repositories, identity is derived from a SHA-256 hash of the root commit set reachable from `HEAD`. The root commit itself is not stored as the identity value.

For non-Git repositories, the fallback is a hash of the resolved local repository path. That fallback is intentionally local-machine-specific.

Caveat: shallow history or history rewriting can change the Git-root-derived identity. In that case Before Deploy may refuse the comparison rather than risk comparing unrelated histories.

## Session contents

`review-session.json` is intentionally smaller than `review.json`. It retains only data needed for longitudinal comparison:

- session/scan ID;
- repository identity hash and identity basis;
- Git revision when available;
- policy digest;
- deterministic finding fingerprints and minimal metadata;
- advisory finding fingerprints and minimal metadata;
- advisory source health/scope state.

It does not retain:

- OCR `thinking`;
- raw source code;
- OCR `existing_code`;
- OCR `suggestion_code`;
- provider credentials;
- raw stderr/stdout;
- waiver secrets or arbitrary tool diagnostics.

## Baseline failures are gate-neutral

A missing, malformed, unsupported, or cross-repository baseline does not gain release authority.

Examples:

```text
status = ERROR
```

or:

```text
status = IDENTITY_MISMATCH
```

are lifecycle diagnostics only. The CLI exit code still follows the current deterministic `PolicyDecision`.

Likewise, failure to write optional session/delta artifacts must be surfaced as a diagnostic warning rather than changing the release decision.

## Architecture

```text
Current deterministic + advisory review
              |
              v
       review-session.json
              |
              | explicit baseline
              v
      fingerprint comparison
              |
      +-------+--------+
      |       |        |
     NEW  PERSISTING  ABSENT_CURRENT
              |
              v
      review-delta.json/md

     diagnostics only

---------------- trust boundary ----------------

      deterministic controls
              |
              v
        PolicyDecision
```
