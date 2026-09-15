# Caller Pilot v2 pre-registration

This document freezes the redesign after the first uncontaminated live GPT-5.6 Luna run of PR #43.

## Frozen v1 result

GitHub Actions run `34971993763` on commit `f062246021a7f6a758e9bc7cf6ccb5cab8be0229` produced `STOP`.

Artifact: `caller-pilot-live-openai`

Artifact digest: `sha256:63493c32176298ec85fd5044a56b490d7ede4df947fa93924da995317179913e`

Stop reasons:

- `NO_EXPLORATION_REQUIRED_RECALL_LIFT`
- `NO_EXPLORATION_ATTRIBUTABLE_TRUE_POSITIVE`
- `EXPLORATION_ATTRIBUTABLE_FP_NOT_LOWER_THAN_TP`

The v1 exploratory run described caller-dependent upload-path and SSRF issues, but emitted their finding locations at helper definitions. The model-visible initial evidence also omitted the absolute source range, which made later helper definitions impossible to locate correctly in repository coordinates.

## v2 hypothesis

The pilot should measure whether `find_callers` adds useful evidence, not whether the model can infer hidden source offsets or guess the evaluator's location convention.

Before the v2 live run, the protocol is changed only as follows:

1. Model-visible initial evidence receives its absolute `source_start_line` and `source_end_line`.
2. The reviewer contract requires initial-only findings to use that supplied source range.
3. When a claim's concrete impact requires caller evidence, the reviewer contract requires the finding location to point at the concrete caller operation/call site shown by the cited caller observation rather than the helper definition.
4. GPT-5.6 Luna remains the model for both paired variants with medium reasoning.
5. Luna token pricing is recorded using the current standard API rates: $0.20/M input, $0.02/M cached input, and $1.20/M output.

## Frozen evaluation

The following are intentionally unchanged for v2:

- the 12 checked-in pilot cases;
- `STATIC-SUFFICIENT`, `EXPLORATION-REQUIRED`, and `FALSE-POSITIVE-TRAP` assignments;
- defect IDs and benchmark locations;
- the `find_callers` implementation and budgets;
- the static variant's lack of tool access;
- the exact-symbol tool boundary;
- the PR41 benchmark matcher;
- all PR43 STOP/GO criteria.

A v2 `GO` is legitimate only if the existing evaluator returns `GO` from a new blinded external Luna run. A `STOP` means redesign again; it does not unlock PR44.
