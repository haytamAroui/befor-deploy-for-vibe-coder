# `find_callers` Pilot Checkpoint

PR43 is the immediate measurement checkpoint after the PR41 harness and PR42 minimal loop.

The checked-in pilot has 12 cases:

- 4 `STATIC-SUFFICIENT` positives;
- 4 `EXPLORATION-REQUIRED` positives;
- 4 `FALSE-POSITIVE-TRAP` negatives.

The experiment must compare exactly one static variant and one exploratory variant. The model/provider/configuration should otherwise be held constant. Multiple repetitions are encouraged and are aggregated by the PR41 harness.

For each case, `cases.json` declares only the initial source range, the symbol eligible for `find_callers`, exact evaluation regions, and—only for positive cases—the defect ID used by the evaluator. Ground-truth labels and trap classification are evaluator data and must not be included in model context.

The exploratory run receives no repository capability except PR42 `find_callers`. The static run uses the same loop with that action disabled.

`evaluate_caller_pilot(...)` returns `GO` only when all of these engineering conditions hold:

1. exploration-required recall is strictly higher than static;
2. at least one true positive is actually attributable to expanded caller evidence;
3. exploration-attributable TP exceeds exploration-attributable FP;
4. false-positive-trap rate does not increase;
5. static-sufficient recall does not regress;
6. all exploratory claims are evidence-supported;
7. all exploratory citations are correctly bound.

Any failure returns `STOP` with reason codes. This is intentionally conservative and is an engineering investment decision, **not** a claim of statistical significance or market superiority.

Scripted/oracle fixtures may validate the harness and decision logic but must never be presented as the pilot outcome. A real provider/model execution must be recorded before PR44 corpus expansion is used to justify further probabilistic architecture.

All pilot artifacts remain `BENCHMARK_DIAGNOSTIC`, `gate_effect=NONE`.
