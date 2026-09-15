# Release Readiness Gate

`docs/PRODUCTION_READINESS_CRITERIA.md` defines the frozen criteria for calling Before Deploy
production-ready. `before_deploy.production_readiness` *evaluates* those criteria, but it is a
diagnostic: it declares `gate_effect = "NONE"` and can be run and ignored.

`before_deploy.readiness_gate` is the part that can stop a release. `.github/workflows/release.yml`
runs it before creating a GitHub Release or publishing to PyPI.

## Why this exists

The `v1.0.0` tag was pushed while the recorded pilot result was `STOP`. Nothing published, but only
by accident: `uv.lock` disagreed with `pyproject.toml` and `uv sync --frozen` failed first. The
release path had no readiness check at all — it ran the test suite and a self-scan, then published.

## Evidence sources

Every readiness field is derived from an artifact built by CI. The gate accepts **no boolean from
the command line**, so a hand-written "everything passed" cannot satisfy it.

| Fields | Source | How it is obtained |
| --- | --- | --- |
| Repeated benchmark (14 fields) | `caller-pilot.json` | Retained artifact of the `production-readiness-luna` workflow run |
| Independent validation (9 fields) | `real-world-validation.json` | Retained `real-world-validation` artifact |
| Operational safety flags + fault scenarios | operational JUnit XML | Derived from a frozen verifier map (below) |
| `assurance_workflow_passed` | assurance JUnit XML | End-to-end integration suite over the fixtures |
| `clean_install_smoke_passed` | smoke JUnit XML | Built distribution installed into an isolated environment |
| `deterministic_ci_passed` | full-suite JUnit XML | No failures or errors (skips tolerated) |
| `retained_evidence_digest_count` | computed | SHA-256 of every artifact the gate consumed |

## Fail-closed behavior

| Situation | Result |
| --- | --- |
| Artifact missing, unreadable, or wrong schema | exit `2` (input error) |
| Declared verifier absent from a JUnit report | exit `2` — the scenario was never exercised |
| Declared verifier failed **or skipped** | scenario is not satisfied → `NOT_READY` |
| Full suite contains any failure or error | `DETERMINISTIC_CI_NOT_GREEN` → `NOT_READY` |
| Any frozen criterion unsatisfied | exit `1` with the reason codes |

Exit `0` happens only when `evaluate_production_readiness` returns `READY`.

A skip is deliberately treated as *absent* evidence for an operational scenario, while a skip in the
full suite is tolerated. Capability-probed tests (symlink support) legitimately skip in CI, but a
skipped scenario verifier means the safety property was never checked.

## The frozen verifier map

`OPERATIONAL_SCENARIO_TESTS` maps each safety flag to the tests that establish it. Renaming or
deleting one of those tests makes the gate fail closed rather than silently pass; a unit test
asserts every declared node id still exists in the repository.

Parametrized verifiers are matched by base node id and **every** parameter must pass.

## Workflow requirements

Before the gate step, `release.yml`:

1. resolves the most recent **successful** run of `production-readiness-luna.yml` on
   `prod/readiness-luna`;
2. refuses to proceed unless that run's commit is an **ancestor** of the commit being released;
3. refuses evidence older than `READINESS_MAX_AGE_DAYS` (default 30);
4. downloads the retained artifact from that specific run.

Release and publish steps come after the gate, so a blocked gate means nothing is built into a
release. The gate report is retained as the `release-gate` artifact.

## Running it locally

```bash
before-deploy-readiness-gate \
  --pilot-report          readiness-evidence/caller-pilot.json \
  --real-world-report     readiness-evidence/real-world-validation.json \
  --operational-report    reports/release-gate/operational-junit.xml \
  --assurance-report      reports/release-gate/assurance-junit.xml \
  --smoke-report          reports/release-gate/smoke-junit.xml \
  --full-suite-report     reports/release-gate/full-suite-junit.xml \
  --output-dir            reports/release-gate
```

Locally the clean-install smoke skips unless `PREFLIGHT_CLEAN_INSTALL=1` is set, so a local run
correctly reports `CLEAN_INSTALL_SMOKE_NOT_GREEN`.

## Current status

The gate is expected to **block** today. The retained pilot result is `STOP`, the §3 independent
validation harness has no paired run records, and no clean-install smoke runs outside the release
workflow. Until those produce a `GO`, `READY` is unreachable — which is the intended behavior.
