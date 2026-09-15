# `find_callers` Pilot Checkpoint

PR43 is the immediate measurement checkpoint after the PR41 harness and PR42 minimal loop.

The checked-in pilot has 12 cases:

- 4 `STATIC-SUFFICIENT` positives;
- 4 `EXPLORATION-REQUIRED` positives;
- 4 `FALSE-POSITIVE-TRAP` negatives.

The experiment must compare exactly one static variant and one exploratory variant. The model/provider/configuration must otherwise be held constant. Multiple repetitions are encouraged and are aggregated by the PR41 harness.

## Blindness requirements

`cases.json` is evaluator data. The live model must never receive case class, defect ID, evaluation regions, or the full case definition.

The fixture repository deliberately uses neutral file names, neutral symbols, and opaque case IDs. This matters because names such as `trap`, `exploration`, or `static` would leak the hypothesis class even if the explicit label were omitted.

`prepare_initial_evidence(...)` materializes only the declared initial range. The provider-neutral bridge in `caller_pilot_runner.py` sends only:

- the exact initial evidence;
- same-run `find_callers` observations;
- the model/provider identity;
- the fixed action/tool contract.

It does not send case class, defect ID, or evaluation regions. For an exploratory case, the only allowed tool target is that case's declared symbol. A request for any other symbol is rejected before PR42 can execute it. The static variant receives no tool action.

Each model turn is an independent subprocess invocation. The bridge command must itself avoid granting the model any additional repository, shell, search, or evaluator access. The JSON protocol is transport, not a sandbox.

## Running a real pilot

The external bridge command reads one JSON request from stdin and writes one JSON response to stdout. It is responsible only for invoking the chosen provider/model and translating that provider's response to the strict bridge schema. This keeps provider SDKs and native provider architecture out of the pre-evidence phase.

Example:

```bash
before-deploy-caller-pilot \
  --provider your-provider \
  --model your-model \
  --bridge-command-json '["python","/absolute/path/to/model_bridge.py"]' \
  --output-dir .artifacts/caller-pilot \
  --repetitions 3
```

The same bridge command, provider, and model are used for both variants. The only experimental difference is whether `find_callers` is available.

A bridge response must use `before-deploy-caller-bridge-response-v1` and return either:

```json
{
  "schema_version": "before-deploy-caller-bridge-response-v1",
  "action": "FIND_CALLERS",
  "call_id": "call-1",
  "symbol": "the_allowed_symbol",
  "usage": {
    "input_tokens": 100,
    "output_tokens": 10,
    "cost_microusd": 25
  }
}
```

or:

```json
{
  "schema_version": "before-deploy-caller-bridge-response-v1",
  "action": "FINAL",
  "claims": [],
  "usage": {
    "input_tokens": 100,
    "output_tokens": 10,
    "cost_microusd": 25
  }
}
```

Final claims cite only evidence IDs present in the bridge request. PR42 independently derives whether a claim depended on expanded context.

The runner writes paired advisory outputs, a PR41 comparative manifest/report, and the PR43 STOP/GO report.

## STOP/GO rule

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
