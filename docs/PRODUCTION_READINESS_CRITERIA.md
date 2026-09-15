# Production Readiness Criteria

These criteria are frozen before reading the repeated `caller-pilot-v2` Luna result. They are engineering release criteria for Before Deploy itself; they do **not** give probabilistic advisory output deterministic release authority.

## 1. Repeated blinded Luna benchmark

The expanded controlled benchmark must satisfy all of the following with `gpt-5.6-luna`:

- at least **5** repetitions for both STATIC and EXPLORATORY variants;
- caller-pilot decision `GO`;
- exploration-required recall lift **>= 0.20**;
- at least **5** exploration-attributable true positives across the repeated experiment;
- exploration-attributable true positives strictly greater than exploration-attributable false positives;
- false-positive-trap rate delta **<= 0**;
- static-sufficient recall delta **>= 0**;
- exploratory supported-claim rate **1.0**;
- exploratory citation-correct rate **1.0**;
- exploratory prediction stability **>= 0.70**;
- exploratory mean latency per repetition **<= 300,000 ms**;
- exploratory mean model cost per repetition **<= 250,000 micro-USD ($0.25)**.

A workflow or provider/protocol failure is a failed readiness run, not a skipped or successful run.

### Metric definitions

These definitions are frozen before the next repeated run and are changes of measurement, not of
threshold. See `docs/EXPLORATION_HARDENING_PLAN.md` for the rationale and the recorded failing
result that motivated them.

- **Exploratory prediction stability** is the mean pairwise Jaccard similarity of the normalized
  advisory claim-key sets across the exploratory repetitions. A claim key is the hash of
  `{source, category, path, start_line}`, which excludes model-authored prose and model-judgement
  fields. This is the gating measurement for the `0.70` threshold above.
- **Exact prediction stability** is the mean pairwise Jaccard similarity of the exact advisory
  fingerprint sets. It is reported on every run as a diagnostic, and it cannot satisfy or waive
  the `0.70` threshold.

No result of the previous run may be reused for either measurement. Both must come from the same
new repeated run.

## 2. Operational fault tolerance

Before Deploy must have deterministic tests proving that external advisory failures remain advisory failures and cannot alter deterministic release authority. The production path must cover:

- bounded retry for transient HTTP 408/409/429/5xx and transport failures;
- at most **3 provider attempts** per model turn by default;
- no automatic retry for authentication/authorization and other non-transient client errors;
- bounded retry delay;
- malformed/non-JSON/structurally invalid provider output fails safely;
- missing credentials fail explicitly;
- subprocess/provider timeout fails safely;
- explicit total token/cost ceilings for repeated benchmark execution;
- advisory errors retain `gate_effect=NONE` and do not create deterministic release evidence.

## 3. Independent real-world validation

Controlled fixtures are necessary but not sufficient. Production readiness requires a blinded benchmark over frozen pre-fix snapshots from at least **3 unrelated public repositories** containing at least **6 independently documented historical defects**.

The reviewer must not receive CVE/advisory names, fix commits, hidden labels, or expected locations. The real-world validation must satisfy:

- exploratory known-defect recall **>= 0.60**;
- exploration-attributable true positives strictly greater than exploration-attributable false positives;
- exploratory false-positive rate does not exceed the static baseline;
- every credited finding cites evidence supplied in that run;
- no benchmark-label leakage is present in model-visible identifiers or prompts.

## 4. Full assurance workflow

Evidence Challenge, Assurance Case, and verification-obligation paths must be exercised end-to-end. Tests must prove:

- challenge/assurance output remains advisory and `gate_effect=NONE`;
- an AI proposal cannot freeze its own verification obligation;
- frozen obligations contain no arbitrary model-authored command/argv execution authority;
- deterministic verification results attach only to frozen obligations;
- challenge or verification records cannot directly change deterministic release disposition.

## 5. Release engineering

Before declaring Before Deploy production-ready:

- the complete deterministic CI suite is green on the candidate tree;
- a clean-environment package install and CLI smoke test pass;
- production-readiness evidence is retained with run IDs and content digests;
- all required criteria above are evaluated by a deterministic readiness report;
- no failed criterion is waived by changing thresholds after observing results.

Until every section passes, the project status is **NOT_READY** or **PRODUCTION_CANDIDATE**, not production-ready.
