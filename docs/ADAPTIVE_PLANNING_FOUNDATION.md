# Adaptive Planning Foundation

**Status:** Implemented deterministic foundation

Before Deploy now records a versioned **Security Analysis Plan** for every completed scan. The plan is a redaction-safe explanation of which approved capabilities were selected from bounded repository evidence. It is not a release decision, a scanner executor, a waiver mechanism, or an AI agent.

> **Authority boundary:** Only the versioned policy engine can return `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED`. Evidence collection, planning, and coverage auditing are diagnostic. They cannot add a capability, mutate a policy, suppress a finding, execute project code, create a waiver, merge, deploy, or access source values outside the existing bounded scan scope.

## 1. Deterministic flow

| Stage | Input | Output | Authority |
|---|---|---|---|
| Repository inventory | Bounded working-tree files | Stable file scope, digest, and limitations | Defines scan scope only. |
| Repository evidence collector | Inventory and project profile | Redaction-safe technology, CI, API, container, and IaC signals | Proves only observable repository facts. |
| Requirements evidence collector | Explicit bounded documentation files | Declared-domain signals with path and line only | Does not prove implementation. |
| Adaptive project profiler | Extensions, manifests, lockfiles, fixed markers | Languages, frameworks, package managers, and compatibility gaps | Selects no new policy. |
| Security analysis planner | Profile, evidence, and already-compatible configured controls | Versioned selected capabilities, coverage expectations, and exclusions | Describes existing approved selections only. |
| Coverage auditor | Analysis plan and observed control executions | Deterministic coverage statuses | Cannot affect the policy result. |
| Policy engine | Normalized executions, findings, waivers, selected policy | Final release outcome | Sole release authority. |

The planner runs only after the configured controls have been filtered through the existing compatibility catalog. It cannot discover a tool on `PATH`, activate an unconfigured adapter, or run a capability merely because a document mentions it.

## 2. Evidence contract

An `EvidenceSignal` contains a versioned signal ID, category, title, path, optional line, and small redaction-safe metadata. It deliberately excludes matching sentences, source excerpts, dependency values, tokens, environment values, and arbitrary document content.

| Evidence family | Deterministic signals in this milestone | Scope boundary |
|---|---|---|
| Repository profile | Detected languages, frameworks, and package-manager/lockfile evidence | Reuses the existing bounded inventory and fixed profile markers. |
| CI/CD | GitHub Actions workflow path | Detects a visible workflow file; does not evaluate hosted runtime behavior. |
| API | OpenAPI or Swagger document path | Identifies an API contract artifact; does not validate endpoint authorization. |
| Container | Dockerfile or Compose file path | Identifies container artifacts; no container-image or runtime analysis is installed. |
| Infrastructure as code | Terraform file path | Identifies `.tf` configuration; no IaC scanner is installed in this milestone. |
| Declared requirements | Authentication, API, file-upload, payment, and personal-data phrases in named Markdown documents | Creates a declared-domain signal only; it never concludes that the feature exists or is secure. |

The requirements collector inspects only root `README.*`, root `architecture.md`, `design.md`, `requirements.md`, `spec.md`, `specification.md`, and Markdown files under `docs/`. It does **not** treat Python dependency files such as `requirements.txt` as product requirements, and it ignores unbounded generic text files. Each recognized domain is reported once at its first deterministic document location.

## 3. Security Analysis Plan

`SecurityAnalysisPlan` is immutable and contains a plan version, profile version, capability-catalog version, ordered evidence, and the selections listed below.

| Plan field | Meaning in this milestone |
|---|---|
| `control_selections` | Native approved controls that the configured policy selected and the adaptive compatibility catalog marked runnable. |
| `adapter_selections` | Existing external-control adapters only when the selected policy explicitly configures them and they are compatible. No adapter is auto-enabled. |
| `skill_selections` | Always empty. Declarative skill packs are intentionally deferred; no executable skill code exists. |
| `coverage_expectations` | Domains derived from observed technology, repository artifacts, and declared-document signals. |
| `exclusions` | Existing profile coverage gaps plus explicit foundation limits, including the absence of loaded skill packs. |

Each selected capability includes its fixed ID/version, type, deterministic rationale, and evidence IDs. The plan is therefore reproducible from the same repository scope, policy-selected controls, and versioned catalogs. It remains descriptive: execution still occurs through the existing bounded control adapters.

## 4. Coverage audit

The coverage auditor uses only the plan, the versioned domain-to-capability catalog, and observed execution statuses. It does not inspect raw source, make vulnerability assertions, or calculate a percentage score.

| Status | Meaning |
|---|---|
| `COVERED` | Every selected capability mapped to the domain completed. This is not a claim of exhaustive analysis or deployment security. |
| `PARTIAL` | At least one selected mapped capability did not complete. |
| `UNAVAILABLE` | The catalog has no approved capability for the observed domain, or it was not selected by the configured policy. |
| `NOT_APPLICABLE` | A mapped capability was explicitly recorded as incompatible for the repository. |
| `DECLARED_REVIEW_REQUIRED` | A bounded documentation signal declared a domain. It requires implementation review; the signal is not a finding and cannot alter the gate. |

Current mapped coverage is intentionally modest: repository-wide secrets, Python source/configuration, FastAPI, Next.js static controls, dependency-manifest checks, and GitHub Actions. Container and Terraform evidence correctly become visible `UNAVAILABLE` states because no corresponding scanner is installed. This makes the limitation observable rather than implying coverage.

## 5. Reports and redaction

The complete plan and audit are included in the canonical JSON report. Markdown exposes readable tables of selected capabilities, coverage expectations, exclusions, and audit states. SARIF stores the normalized plan and coverage audit under Before Deploy properties. None of these report paths include matching requirement text or raw source excerpts.

## 6. Deferred expansion

The next evolution may add declarative skill metadata, but not agent code. A future skill must have a fixed ID/version, deterministic applicability conditions, approved control/adapter references, documented exclusions, validation fixtures, and no arbitrary executable payload. A future read-only AI advisor may explain normalized redacted plan/audit output, but it cannot determine applicability, choose tools, execute commands, change policy, create waivers, or influence the gate outcome.
