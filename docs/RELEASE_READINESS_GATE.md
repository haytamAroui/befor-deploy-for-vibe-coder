# Release Readiness Gate

`before_deploy.readiness_gate` is the part of the platform that can stop a release.
`.github/workflows/release.yml` runs it before creating a GitHub Release or publishing to PyPI.

## Two tiers, deliberately not one gate

The frozen criteria in `docs/PRODUCTION_READINESS_CRITERIA.md` mix two different kinds of claim.
Tier A is a statement about software this repository builds and ships. Tier B is a measurement of an
external model. Only Tier A is allowed to block a release.

| Tier | Criteria | Evidence producer | Effect on release |
| --- | --- | --- | --- |
| **A — Software release readiness** | §2 operational fault tolerance, §4 full assurance workflow, §5 release engineering | `release.yml` (deterministic) | **Blocks** (`authority=RELEASE_GATE`, `gate_effect=BLOCKS_RELEASE`) |
| **B — Model evaluation** | §1 repeated blinded benchmark, §3 independent real-world validation | `production-readiness-luna.yml`, `real-world-validation.yml` | **Reported only** (`authority=BENCHMARK_DIAGNOSTIC`, `gate_effect=NONE`) |

### Why the split exists

Tier B originally gated the release. That made the shippable artifact of a deterministic security
engine depend on a live third-party model run: an API outage, a deprecation, a price change, or a
model update could freeze releases of software that had not changed. The coupling also meant a
`v1.0.0` tag could not publish while the recorded benchmark result was `STOP`, despite the benchmark
module documenting `gate_effect = "NONE"`.

Splitting them does **not** delete or relax any criterion. Every criterion is still implemented and
still evaluated; what changed is that §1 and §3 no longer decide whether this software can ship.

## Tier A: what must hold to release

| Criterion | Evidence artifact | How it is derived |
| --- | --- | --- |
| `deterministic_ci_passed` | `full-suite-junit.xml` | No failures or errors (skips tolerated) |
| `lint_passed` | `lint-report.json` | `ruff check --output-format json` returns an empty array |
| `self_scan_passed` | `self-scan/report.json` | `scan.decision.outcome == "PASS"` and zero blocking findings and zero error controls |
| `distribution_built` | `dist/` | At least one `.whl` **and** one `.tar.gz` present; both are digested |
| `assurance_workflow_passed` | `assurance-junit.xml` | End-to-end integration suite over the fixtures |
| `clean_install_smoke_passed` | `smoke-junit.xml` | Built distribution installed into an isolated environment |
| operational fault coverage | `operational-junit.xml` | All six §2 safety flags satisfied (below) |

Reason codes when unsatisfied: `DETERMINISTIC_CI_NOT_GREEN`, `LINT_NOT_CLEAN`, `SELF_SCAN_NOT_PASS`,
`DISTRIBUTION_NOT_BUILT`, `FULL_ASSURANCE_WORKFLOW_NOT_PROVEN`, `CLEAN_INSTALL_SMOKE_NOT_GREEN`,
`OPERATIONAL_FAULT_COVERAGE_INCOMPLETE`.

The gate accepts **no boolean from the command line**. Every field is derived from a CI-produced
artifact, so a hand-written "everything passed" cannot satisfy it.

`NOT_EVALUATED` is deliberately *not* an accepted self-scan outcome. A scan that ran no control has
not checked anything, so it cannot certify a build.

### Operational safety flags (§2)

Each flag is true only when every declared verifier is present in the operational JUnit report and
passed. The verifiers are frozen in `OPERATIONAL_SCENARIO_TESTS`:

`bounded_retry_passed`, `malformed_output_safe`, `missing_credentials_safe`, `timeout_safe`,
`cost_budget_enforced`, `advisory_authority_isolated`.

A verifier that is **absent** from the report is an input error: the scenario was never exercised,
which is not the same as passing. A verifier that **failed or skipped** does not satisfy the
scenario. Reviewed together these are the §2 invariant: an advisory or provider failure must remain
an advisory failure and cannot alter deterministic release authority.

## Tier B: what is reported but not gating

The gate reads Tier B evidence when it is supplied and reports it in `release-gate.json`,
`release-gate.md`, and the workflow step summary under a heading that states it does not block the
release. The release workflow does **not** download benchmark artifacts and enforces no ancestry or
freshness rule over them, because those rules existed only to bind a release to a model run.

The repeated-benchmark block reports the recorded decision, exploration-required recall lift, the
false-positive-trap and static-sufficient deltas, and exploratory prediction stability. The §3 block
reports one of three states:

| State | Meaning |
| --- | --- |
| `MEASURED` | A validated §3 report with a measured `recall`. |
| `DEFINITION_ONLY` | A corpus definition: the pinned repositories and labelled defects exist, but exploratory recall has never been measured. |
| `ABSENT` | No §3 artifact was supplied. |

`DEFINITION_ONLY` exists because `real-world-validation.yml` can only validate corpus provenance: it
invokes `before-deploy-real-world-validation` without `--run`, and **no producer for paired
static/exploratory run records exists in this repository**. Until one does, §3 cannot be measured,
and the report says so in those words instead of presenting a corpus definition as a §3 pass.

Because Tier B is non-blocking, **malformed Tier B evidence cannot block a release either.** It
degrades to "unsupplied". This is deliberate: a diagnostic that can halt a release has been
re-promoted into a gate.

## Fail-closed behavior

| Situation | Result |
| --- | --- |
| Any Tier A artifact missing, unreadable, or schema-invalid | exit `2` (input error) |
| Declared verifier absent from a JUnit report | exit `2` — the scenario was never exercised |
| Declared verifier failed **or skipped** | criterion unsatisfied → `NOT_READY` (exit `1`) |
| Full suite contains any failure or error | `DETERMINISTIC_CI_NOT_GREEN` → `NOT_READY` |
| Any Tier A criterion unsatisfied | exit `1` with the reason codes |
| Tier B artifact missing, malformed, or failing | reported; exit code unchanged |

Exit `0` happens only when every Tier A criterion holds. A pass asserts deterministic software
readiness. It does **not** assert that the advisory or model-evaluation planes are mature, and it
does not grant AI findings release authority.

## Running the gate locally

```bash
uv run before-deploy-readiness-gate \
  --full-suite-report reports/release-gate/full-suite-junit.xml \
  --lint-report reports/release-gate/lint-report.json \
  --self-scan-report reports/release-gate/self-scan/report.json \
  --operational-report reports/release-gate/operational-junit.xml \
  --assurance-report reports/release-gate/assurance-junit.xml \
  --smoke-report reports/release-gate/smoke-junit.xml \
  --distribution-dir dist \
  --output-dir reports/release-gate
```

Add `--pilot-report` and `--real-world-report` to include Tier B evidence in the report. Both are
optional and neither changes the exit code.
