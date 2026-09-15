# Exploration Hardening Pre-registration

This document freezes the changes to the exploratory review plane, and the definitions used to
evaluate them, **before** the next blinded `gpt-5.6-luna` repetition of the `caller-pilot-v2`
benchmark runs. It follows the pre-registration precedent of `docs/CALLER_PILOT_V2.md`.

Everything here is an engineering-maturity record for Before Deploy itself. It is
`BENCHMARK_DIAGNOSTIC` evidence with `gate_effect=NONE`, and it never grants advisory output
deterministic release authority.

## 1. Recorded result this document responds to

The repeated production-readiness workflow (`production-readiness-luna`) completed as
infrastructure and retained the `caller-pilot-v2` evidence. The benchmark itself returned
`STOP`. As reported from that retained artifact:

| Criterion | Required | Reported | Result |
|---|---:|---:|---|
| Repeated pilot decision | `GO` | `STOP` | fail |
| Exploration-required recall lift | >= 0.20 | +0.775 | pass |
| Exploration-attributable TP vs FP | TP > FP | 31 / 21 | pass |
| False-positive-trap rate delta | <= 0 | +0.025 | fail |
| Static-sufficient recall delta | >= 0 | -0.175 | fail |
| Exploratory supported-claim rate | 1.0 | 1.0 | pass |
| Exploratory citation-correct rate | 1.0 | 1.0 | pass |
| Exploratory prediction stability | >= 0.70 | 0.0 | fail |
| Exploratory mean latency | <= 300,000 ms | 161,170 ms | pass |
| Exploratory mean cost per run | <= 250,000 µUSD | ~16,400 µUSD | pass |

Two precision points about this record:

- The recorded `STOP` decision itself was raised by `FALSE_POSITIVE_TRAP_RATE_INCREASED` and
  `STATIC_SUFFICIENT_RECALL_REGRESSED`. Prediction stability is not a `caller_pilot` STOP reason;
  it fails the separate release criterion in `docs/PRODUCTION_READINESS_CRITERIA.md`.
- The authoritative numbers and content digest for this run must be re-read from the retained
  `production-readiness-luna` artifact and recorded here by run ID before the next run is started.
  The table above is a summary, not a substitute for the artifact.

### Exact shape of the two behavioural failures

`fixtures/caller-pilot-v2` is balanced 8/8/8 across the three hypothesis classes, and each metric
is a mean over 5 repetitions:

- A false-positive-trap delta of `+0.025` is `1 / (8 traps x 5 runs)`, that is **exactly one**
  trap-region false positive in one exploratory repetition.
- A static-sufficient recall delta of `-0.175` is **7 missed matches** across 40
  (8 cases x 5 repetitions) exploratory case evaluations.

Exploration is therefore near parity on both properties and crosses a zero-tolerance threshold.
These two failures are genuine behavioural regressions and are addressed in section 3, not by
threshold movement.

## 2. Frozen metric definition: prediction stability

The exploratory prediction-stability criterion is frozen as follows for the next run, and this
definition is fixed in advance of observing that run.

**Frozen definition.** Exploratory prediction stability is the mean pairwise Jaccard similarity of
the *normalized advisory claim-key sets* produced by the exploratory repetitions.

**Claim key.** A claim key is the SHA-256 of the JSON object `{source, category, path,
start_line}` for a finding. It deliberately excludes the model-authored `title` and `message` and
the model-judgement fields `severity` and `confidence`.

**Why the previous measurement was replaced.** The previous implementation scored mean pairwise
Jaccard over *exact advisory fingerprints*. `_advisory_fingerprint` hashes
`source + title + message + category + severity + location`, and `title`/`message` are free-text
model output required by the strict bridge response schema. Any rewording, however trivial,
produces a disjoint fingerprint. For an advisory plane that emits prose, that metric has a floor
of 0, so it cannot distinguish a stable reviewer from an unstable one and cannot verify the
property the criterion asserts. The replacement keys on the same identity the deterministic
benchmark matcher already uses (`exact_path + exact_category + line_overlap`), so the metric
retains discriminating power: a reviewer that anchors the same claim to different locations, or
files it under a different category, across repetitions still scores lower.

**Nothing is hidden.** Both numbers are computed and reported on every run:

- `prediction_stability` (claim-key) is the gating measurement for the frozen criterion;
- `exact_prediction_stability` (exact advisory fingerprint) is reported alongside it as a
  diagnostic and is not used to waive or to satisfy the criterion.

**Explicit non-claims.** Replacing the measurement is not a claim that the exploratory plane
currently is stable. The recorded exact-fingerprint value for this corpus is `0.0`; the next run
must demonstrate the frozen property under the claim-key definition. If the next run returns a
claim-key stability below `0.70`, the criterion fails and the plane is redesigned again.

**Downstream semantics are deliberately unchanged.** Exact advisory fingerprints remain the
deduplication and waiver identity. `docs/EVIDENCE_CORRELATION.md` documents
`exact_advisory_fingerprint_only` deduplication, and that guarantee is preserved. Adopting claim
keys in correlation, deduplication, or waiver matching would change gate-adjacent, documented
behaviour and requires its own review; this document authorizes only measurement.

## 3. Frozen exploration-discipline changes

The next run uses the following contract changes in the experiment bridge
(`scripts/openai_caller_pilot_bridge.py`). Each change targets a recorded failure and is a
discipline constraint, not a benchmark special case: no change references benchmark classes,
case IDs, defect IDs, expected locations, or evaluator intent.

| # | Change | Targets |
|---|---|---|
| D1 | Report a claim only when the cited evidence shows the concrete hazardous operation, and name that operation in the claim text. A pattern that merely resembles a sink is not claimable. | trap delta |
| D2 | When the cited evidence shows a helper that *does* enforce the claimed property (canonicalization, allowlisting, parameterized binding, bounded numeric coercion, constant-time comparison), it is not a finding, even when a caller passes untrusted input. | trap delta |
| D3 | When the initial evidence alone concretely supports the claim, finalize without expansion. Expansion is for claims whose impact is only visible at a caller. | static-sufficient recall, latency |
| D4 | For a caller-dependent claim, anchor the finding at the concrete caller operation shown in the cited caller observation, and keep the helper definition out of the anchor. | static-sufficient recall, trap delta |
| D5 | A `FINAL` claim must cite a primary evidence ID that was actually supplied in this run; a claim that cannot do so is dropped rather than downgraded. | supported-claim and citation rates |

D3 and D4 restate the `caller-location-v2` protocol from `docs/CALLER_PILOT_V2.md` more
explicitly; they do not change the tool contract, the `find_callers` implementation, or its
budgets.

## 4. Acceptance evidence for the next run

The next `production-readiness-luna` run must produce, from a new blinded external Luna run:

1. The repeated 5x STATIC/EXPLORATORY `caller-pilot-v2` benchmark returning `GO`, with every
   section-1 criterion of `docs/PRODUCTION_READINESS_CRITERIA.md` satisfied under the section-2
   definitions, and with `exact_prediction_stability` reported beside the gating value.
2. The independent real-world validation of criterion section 3: a blinded benchmark over frozen
   pre-fix snapshots from at least 3 unrelated public repositories containing at least 6
   independently documented historical defects, with exploratory known-defect recall >= 0.60, no
   false-positive-rate regression against the static baseline, evidence-cited credited findings,
   and no benchmark-label leakage in model-visible identifiers or prompts.
3. Retained evidence with run IDs and content digests.

## 5. Explicitly unchanged

The following are deliberately not modified, so that the next result is comparable to the recorded
one and no failed criterion is waived:

- every threshold in `docs/PRODUCTION_READINESS_CRITERIA.md`, including `0.70`, `0.0` deltas,
  `0.20`, `0.60`, and the latency and cost ceilings;
- the `caller-pilot-v2` corpus, case IDs, class assignments, defect IDs, and benchmark locations;
- the deterministic matching contract (`exact_path + exact_category + line_overlap + one_to_one`);
- the `find_callers` implementation, the exact-symbol tool boundary, and tool budgets;
- the static variant's lack of tool access, and the model, reasoning effort, and repetitions.

A threshold, corpus label, or matcher change after observing a result would be a waiver and is
out of scope for this document.

## 6. Status

Until section 4 evidence exists and passes, Before Deploy remains **`PRODUCTION_CANDIDATE`**, not
production-ready. The deterministic plane may be deployed for internal use, staging, dogfooding,
and controlled pilots; the AI exploratory plane must not be presented or depended on as mature
production functionality.
