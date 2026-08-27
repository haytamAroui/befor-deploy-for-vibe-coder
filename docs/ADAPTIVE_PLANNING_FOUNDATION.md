# Adaptive Planning Foundation

**Status:** Implemented deterministic foundation

Before Deploy now records a versioned **Security Analysis Plan** for every completed scan. The plan is a redaction-safe explanation of which approved registry capabilities were selected from bounded repository evidence and the active policy. It is not a release decision, a scanner executor, a waiver mechanism, or an AI agent.

> **Authority boundary:** Only the versioned policy engine can return `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED`. Evidence collection, planning, and coverage auditing are diagnostic. They cannot add a capability, mutate a policy, suppress a finding, execute project code, create a waiver, merge, deploy, or access source values outside the existing bounded scan scope.

## 1. Deterministic flow

| Stage | Input | Output | Authority |
|---|---|---|---|
| Repository inventory | Bounded working-tree files | Stable file scope, digest, and limitations | Defines scan scope only. |
| Repository evidence collector | Inventory and project profile | Redaction-safe technology, CI, API, container, and IaC signals | Proves only observable repository facts. |
| Requirements evidence collector | Explicit bounded documentation files | Declared-domain signals with path and line only | Does not prove implementation. |
| Adaptive project profiler | Extensions, manifests, lockfiles, fixed markers | Languages, frameworks, package managers, and compatibility gaps | Selects no new policy. |
| Declarative capability registry | Packaged, version-controlled YAML manifests | Validated approved capability definitions and semantic catalog digest | Metadata-only; cannot execute code or configure a tool. |
| Security domain + control catalog | Packaged, version-controlled YAML taxonomy | Versioned `DOMAIN-` definitions, reviewed `CONTROL-` contracts, informative references, and semantic catalog digest | Informational only; cannot add a capability, certify compliance, or set policy. |
| Security analysis planner | Profile, evidence, both catalogs, and already-compatible configured controls | Versioned selected capabilities with policy/catalog provenance, domain expectations, and exclusions | Describes existing approved selections only. |
| Coverage auditor | Analysis plan, both catalogs, profile, and observed control executions | Deterministic domain and technology coverage statuses | Cannot affect the policy result. |
| Policy engine | Normalized executions, findings, waivers, selected policy | Final release outcome | Sole release authority. |

The planner runs only after the configured controls have been filtered through the existing compatibility catalog. It cannot discover a tool on `PATH`, activate an unconfigured adapter, or run a capability merely because a document mentions it.

## 2. Evidence contract

An `EvidenceSignal` contains a versioned signal ID, category, title, path, optional line, and small redaction-safe metadata. It deliberately excludes matching sentences, source excerpts, dependency values, tokens, environment values, and arbitrary document content.

| Evidence family | Deterministic signals in this milestone | Scope boundary |
|---|---|---|
| Repository profile | Detected languages, frameworks, and package-manager/lockfile evidence | Reuses the existing bounded inventory and fixed profile markers. |
| CI/CD | GitHub Actions workflow path | Detects a visible workflow file; does not evaluate hosted runtime behavior. |
| API | OpenAPI or Swagger document path | Identifies an API contract artifact; does not validate endpoint authorization. |
| Container | Dockerfile, Containerfile, or Compose file path | Identifies container artifacts. The opt-in Trivy adapter covers only staged Dockerfile/Containerfile configuration; it does not inspect images, Compose, registries, or runtime state. |
| Infrastructure as code | Terraform file path | Identifies `.tf` configuration. The opt-in Trivy adapter covers only staged Terraform `.tf` configuration; it does not inspect plans, tfvars, modules, providers, state, or cloud runtime state. |
| Declared requirements | Authentication, API, file-upload, payment, and personal-data phrases in named Markdown documents | Creates a declared-domain signal only; it never concludes that the feature exists or is secure. |

The requirements collector inspects only root `README.*`, root `architecture.md`, `design.md`, `requirements.md`, `spec.md`, `specification.md`, and Markdown files under `docs/`. It does **not** treat Python dependency files such as `requirements.txt` as product requirements, and it ignores unbounded generic text files. Each recognized domain is reported once at its first deterministic document location.

## 3. Security Analysis Plan

`SecurityAnalysisPlan` is immutable and contains a plan version, profile version, policy name/digest, capability-catalog version/digest, security-domain-catalog version/digest, ordered evidence, and the selections listed below.

| Plan field | Meaning in this milestone |
|---|---|
| `control_selections` | Native approved controls that the configured policy selected and the adaptive compatibility catalog marked runnable. |
| `adapter_selections` | Existing external-control adapters only when the selected policy explicitly configures them and they are compatible. No adapter is auto-enabled. |
| `skill_selections` | Always empty. Declarative skill packs are intentionally deferred; no executable skill code exists. |
| `coverage_expectations` | Stable catalog `DOMAIN-` entries activated by bounded profile/evidence facts, plus legacy technology visibility and declared-document review expectations. |
| `exclusions` | Existing profile coverage gaps plus explicit foundation limits, including the absence of loaded skill packs. |

Each selected capability includes its fixed ID/version, type, deterministic rationale, and evidence IDs. The plan is therefore reproducible from the same repository scope, policy-selected controls, and versioned catalogs. It remains descriptive: execution still occurs through the existing bounded control adapters.

## 4. Coverage audit

The coverage auditor uses only the plan, the versioned capability registry, the separate Security Domain + Control Catalog, and observed execution statuses. It does not inspect raw source, make vulnerability assertions, or calculate a percentage score.

| Status | Meaning |
|---|---|
| `COVERED` | Every selected capability mapped to the domain completed. This is not a claim of exhaustive analysis or deployment security. |
| `PARTIAL` | At least one selected mapped capability did not complete without an execution error. |
| `ERROR` | A selected mapped capability returned an execution error; this remains distinct from security findings. |
| `UNAVAILABLE` | The registry has no approved capability for the observed domain. |
| `NOT_SELECTED` | A compatible approved capability exists, but the active policy did not select it. |
| `NOT_APPLICABLE` | All mapped approved capabilities are incompatible with the repository. |
| `DECLARED_REVIEW_REQUIRED` | A bounded documentation signal declared a domain. It requires implementation review; the signal is not a finding and cannot alter the gate. |

Current mapped coverage is intentionally modest: repository-wide secrets, Python direct/local SQL plus a separately opt-in one-alias SQL contract and configuration, FastAPI static route declarations with metadata-only dynamic path/method/direct-`APIRouter`-prefix review, one opt-in root Laravel Composer lockfile-presence contract, one opt-in conventional Rust binary Cargo lockfile-presence contract, one opt-in conventional Rails Gemfile lockfile-presence contract, three Next.js static controls, separate bounded module-level and named-inline Server Action local-guard-marker contracts, dependency-manifest checks, GitHub Actions, and an opt-in staged Trivy Dockerfile/Containerfile/Terraform configuration adapter. The FastAPI review metadata does not resolve a prefix value, derive an effective path, or create a coverage state, finding, or policy input. The Laravel contract checks only one root direct-`require`/`artisan` static form and root lockfile presence; it does not validate values, lock contents, integrity, vulnerabilities, or runtime behavior. The Rust contract checks only a root direct non-empty `dependencies` table plus conventional `src/main.rs` binary form and root lockfile presence; it does not validate values, lock contents, integrity, vulnerabilities, libraries, workspaces, custom targets, or runtime behavior. The Rails contract checks only a root unindented literal Rails gem declaration plus conventional `config/application.rb` and root lockfile presence; it does not validate values, lock contents, integrity, vulnerabilities, groups, dynamic declarations, libraries, nested projects, or runtime behavior. For a compatible repository, container and Terraform evidence become `NOT_SELECTED` under policies that do not select Trivy, and can become `COVERED`, `PARTIAL`, or `ERROR` only through a selected observed adapter execution. These scope-limited states remain diagnostic and never imply image, runtime, cloud, or comprehensive IaC assurance.

## 5. Reports and redaction

The complete plan, audit, and normalized control executions are included in the canonical JSON report. Markdown exposes readable tables of selected capabilities, coverage expectations, exclusions, audit states, and execution metadata. SARIF stores the normalized plan, coverage audit, and control executions under Before Deploy properties. A structural review state in execution metadata is not a finding, coverage state, or gate input. None of these report paths include matching requirement text or raw source excerpts.

For the taxonomy, control-contract mappings, reference boundary, and exact current coverage limits, see [`SECURITY_DOMAIN_CONTROL_CATALOG.md`](SECURITY_DOMAIN_CONTROL_CATALOG.md).

## 6. Deferred expansion

The next evolution may add declarative skill metadata, but not agent code. A future skill must have a fixed ID/version, deterministic applicability conditions, approved control/adapter references, documented exclusions, validation fixtures, and no arbitrary executable payload. It must resolve only to registry capabilities and meet the strict validation contract in [`DECLARATIVE_CAPABILITY_REGISTRY.md`](DECLARATIVE_CAPABILITY_REGISTRY.md). A future read-only AI advisor may explain normalized redacted plan/audit output, but it cannot determine applicability, choose tools, execute commands, change policy, create waivers, or influence the gate outcome.
