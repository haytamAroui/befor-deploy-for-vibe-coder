# Investigation Trace Graph and Assurance Case

The Assurance Case is a deterministic, gate-neutral provenance view over an advisory finding, the evidence made available to it, bounded investigation steps, and an optional Evidence Challenge assessment.

It does **not** create a second release authority. The schema is `before-deploy-assurance-case-v1`, authority is `ASSURANCE_CASE_ADVISORY`, and gate effect is always `NONE`.

## Graph model

The graph uses stable content-derived identifiers and four primary node kinds:

- `FINDING` — the existing advisory finding fingerprint.
- `EVIDENCE` — a content-free evidence identity carrying only an evidence ID, SHA-256 hash, and `INITIAL` or `EXPANDED` origin.
- `INVESTIGATION` — a bounded action such as `find_callers(symbol)` with explicit input and output evidence IDs.
- `CHALLENGE` / `OBJECTION` — the normalized Evidence Challenge assessment and its structured objections.

Relations are likewise bounded: `HAS_EVIDENCE`, `READS`, `PRODUCES`, `CHALLENGES`, `CITES`, and `PART_OF`. Unknown evidence references and challenge hash drift are rejected during graph construction.

## Assurance posture

The case derives a diagnostic posture from the independent challenge record:

- `UNCHALLENGED`
- `CHALLENGE_SUPPORTED`
- `EVIDENCE_INSUFFICIENT`
- `CLAIM_CONTRADICTED`
- `UNRESOLVED`

These labels summarize advisory evidence state only. They cannot change policy, waivers, scan findings, release state, branch state, deployment state, or deterministic verification results.

## Reproducibility

Evidence content is not copied into the normalized graph. The case records evidence IDs and content hashes, while investigation steps and graph nodes/edges receive deterministic IDs derived from normalized content. The final `AC-*` identifier is derived from the complete normalized trace graph and challenge posture.

This makes later comparison and audit possible without confusing provenance with release authority. Verification obligations are intentionally handled by a later layer where AI may propose obligations but a human must explicitly freeze them before execution.
