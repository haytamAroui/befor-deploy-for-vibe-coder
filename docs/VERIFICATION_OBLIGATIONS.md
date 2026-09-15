# Human-Frozen Verification Obligations and Full Comparison

This layer separates **AI-authored verification ideas** from **human-approved obligations** and from **deterministic verification results**.

## Trust boundary

An AI may propose a `VerificationObligationDraft` describing what should be verified, why, the verification kind, a success criterion, and evidence IDs already inside the supplied trace. The proposal is normalized as `AI_VERIFICATION_PROPOSAL_ADVISORY` with gate effect `NONE`.

A proposal becomes a verification obligation only through an explicit human freeze. The freeze records:

- the immutable proposal ID;
- the reviewer identity supplied by the approval surface;
- an external approval reference;
- the complete frozen success criterion and evidence references.

The resulting `VOB-*` record is content-addressed and has authority `HUMAN_FROZEN_VERIFICATION_PLAN`. It remains gate-neutral: freezing an obligation does not itself pass or block release.

The library deliberately does **not** execute model-authored shell commands. Obligations contain no command or argv field. A bounded external executor may perform the approved verification and attach a deterministic `PASS`, `FAIL`, or `ERROR` result with hashed result evidence. The result is recorded as `DETERMINISTIC_VERIFICATION_EVIDENCE`, still with gate effect `NONE`; deterministic release policy remains a separate authority.

## Verification kinds

The bounded vocabulary is:

- `TEST`
- `STATIC_CHECK`
- `REPRODUCTION`
- `MANUAL_REVIEW`

This keeps the obligation about the required assurance outcome rather than granting the model arbitrary execution authority.

## Full assurance comparison

`before-deploy-full-assurance-comparison-v1` joins the existing PR41 comparative discovery metrics with supplemental challenge and verification metrics for each variant. Each row can therefore report, together:

- precision, recall, F1, exploration-attributable TP/FP;
- prediction stability, tool use, latency, and cost;
- Evidence Challenge outcomes (`SUPPORTED`, `INSUFFICIENT`, `CONTRADICTED`, `UNRESOLVED`);
- verification proposals, human freezes, and freeze rate;
- deterministic verification `PASS` / `FAIL` / `ERROR` counts and pass rate.

The comparison requires exactly one supplemental record for every discovery variant and rejects impossible accounting such as more frozen obligations than proposals or more verification results than frozen obligations.

All full-comparison output remains `BENCHMARK_DIAGNOSTIC` with gate effect `NONE`. It is designed for the final static-vs-exploration-vs-challenge-vs-verification experiment, not for release authorization.

## Deferred live validation

The recorded GPT-5.6 Luna caller-pilot v1 result remains `STOP`. Per the current roadmap execution order, that failed experiment is revisited only after these implementation layers exist. Nothing in this module upgrades, erases, or reinterprets that result.
