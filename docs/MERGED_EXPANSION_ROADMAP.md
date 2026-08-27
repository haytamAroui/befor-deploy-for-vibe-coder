# Before Deploy — Merged Expansion Roadmap

**Status:** Proposed versioned product roadmap, derived from the current implemented repository and the reviewed 21-domain expansion blueprint. This document is **not** a policy profile, an executable plan, a scanner configuration, a compliance assessment, or release authority.

**Baseline:** private `master` at `91979e7` or later. The repository already contains the deterministic evidence → profile → capability registry/domain-control catalog → plan → execution → coverage → policy pipeline, Python/FastAPI and Next.js bounded controls, a Go reference pack, opt-in isolated Gitleaks/Semgrep/Gosec/pip-audit/provenance adapters, and the first bounded staged Trivy Dockerfile/Containerfile/Terraform adapter with a non-executing calibration corpus. [1] [2]

> **Non-negotiable authority rule:** only the versioned deterministic policy engine can produce `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED`. Evidence, profiles, domain metadata, plans, coverage, external scanners, requirements signals, and a future AI layer are diagnostic or detection components only. They cannot approve a release, add a control, change policy, create a waiver, execute target code, merge, or deploy. [1]

## 1. Product intent

Before Deploy is a **technology-adaptive, evidence-driven pre-deployment security gate**. It will steadily expand the quality and breadth of its implemented controls, while showing what remains unselected, unavailable, inapplicable, or review-required. It will not claim that a domain name in a catalog proves coverage, that an absent finding proves security, or that 21 domain definitions are 21 universal controls.

The end-state aspiration is defensible rather than inflated:

> **Before Deploy evaluates versioned security domains through technology-aware control contracts, makes scope and gaps explicit, and lets only deterministic policy decide the configured release outcome.**

## 2. Merged architecture decisions

The strategic blueprint and the existing repository align on the core architecture. The table below records the merged decision rather than reopening settled trust boundaries.

| Architecture concern | Merged decision | Reason and guardrail |
|---|---|---|
| Evidence | Keep bounded repository and requirements evidence, with redaction-safe IDs, paths, lines, and small metadata only. | Evidence proves an observable fact, not implementation, runtime state, or security. |
| Project profile | Keep fixed language/framework/manifest/artifact predicates. | Profiling must not discover tools, interpret arbitrary source semantics, or execute code. |
| Domains | Maintain the 21 foundational domains plus separate extensions where scope would otherwise be blurred. | A domain is a security surface and diagnostic coverage unit, never a compliance claim. |
| Control contracts | Keep the stricter existing mapping: **domain → many contracts; each contract → one capability; each capability → one implementation**. | This avoids ambiguous ownership, preserves normalized finding identity, and makes contract provenance auditable. |
| Capability registry | Keep packaged, closed-list, non-executable manifests only for real, reviewed implementations. | Metadata cannot pre-register future scanners, carry commands/URLs/secrets/arguments, or imply coverage. [2] |
| Adapters | Retain the shared shell-free external-runner model and add one bounded adapter at a time. | Every adapter must be policy-configured, preinstalled, version-verified, isolated, timed/output bounded, redacted, and fail-closed. |
| Findings | Preserve the existing normalized, redaction-safe `Finding` model and separate severity from confidence. | Upstream scanner messages, source excerpts, secrets, resource identifiers, URLs, stdout, and stderr must remain discarded unless a separately reviewed safe field is introduced. |
| Coverage | Keep `COVERED`, `PARTIAL`, `ERROR`, `UNAVAILABLE`, `NOT_SELECTED`, `NOT_APPLICABLE`, and `DECLARED_REVIEW_REQUIRED` diagnostic-only. | A coverage state cannot block or pass a release. A selected required control can fail closed through the policy engine. [1] |
| Policy | Preserve exact-match waivers, expiration, policy digests, configured dispositions, and fail-closed required-control errors. | No scanner, catalog, coverage result, or AI assistant may override policy. |
| AI | Defer a read-only advisory layer until the control/adapter model is mature. | It can later explain redacted reports; it cannot choose tools, run commands, access secrets, modify policy/waivers, merge, deploy, or decide outcomes. |

## 3. Explicitly rejected or deferred blueprint proposals

The reviewed expansion blueprint contains useful long-term ideas, but these entries must not be adopted as immediate work.

| Proposal | Decision | Required condition before reconsideration |
|---|---|---|
| Generic `coverage_requirements` that blocks a release | **Deferred; not part of current policy authority.** | A separate policy-language proposal, threat model, migration design, and full regression review demonstrating that diagnostic coverage remains distinguishable from detection and policy. |
| CodeQL as the next default deep scanner | **Deferred.** | A design proving no repository-controlled build command, no target-code execution, no dependency/network resolution, and a fixed safe build/input strategy for each proposed language. |
| A generic scanner-plugin discovery system | **Rejected.** | No automatic adapter loading is permitted. Future adapters remain explicit reviewed source and closed-list capabilities. |
| Adapter manifests containing executable paths, arguments, URLs, or credentials | **Rejected.** | Never permitted under the current trust model. These values belong, where appropriate, in explicit policy and reviewed adapter code. |
| Repository-supplied Semgrep/CodeQL/Trivy rules or config | **Rejected.** | Only packaged reviewed rule packs or a stage that excludes target configuration may be considered. |
| Bulk refactor to `adapters/`, `findings/`, or new package trees | **Deferred.** | A concrete functional need, migration test plan, and no change to IDs/provenance/authority. |
| Claiming universal language support because extensions are detected | **Rejected.** | A language becomes supported only for the exact controls with real implementations, registered capabilities, contracts, policies, fixtures, and tests. |
| Runtime/cloud/container-image assurance from repository scanning | **Deferred as a separate trust model.** | Explicit credentials, least privilege, network/environment controls, redaction, source-of-truth semantics, and policy boundaries must be designed independently. |

## 4. Delivery invariant for every new control

Each work item below is a **single incremental milestone**. A milestone may not add placeholders, speculative catalog entries, or multiple unrelated scanners.

| Requirement | Mandatory completion evidence |
|---|---|
| Precise contract | Stable `SEC-` implementation ID; one capability manifest; one `CONTROL-` contract; mapped domain IDs; explicit scope/exclusions; no historical-ID break. |
| Controlled applicability | Deterministic profile/evidence predicates or explicit adapter `NOT_APPLICABLE` behavior. |
| Policy authority | A policy-selected control definition with explicit `required` and disposition; no automatic default/strict-CI activation unless that is the separately approved goal. |
| Secure execution | No shell, target commands, target scripts, target code execution, arbitrary build, implicit tool download, inherited secrets, or uncontrolled network resolution. |
| Adapter hardening | Preinstalled pinned version; version verification where usable; controlled stage/cwd; minimal environment; fixed literal arguments; timeout; report-size bound; strict schema/path validation; errors fail closed. |
| Data minimization | Normalized allowed fields only; raw source, secrets, scanner stdout/stderr, snippets, target metadata, URLs, and scanner-only suppression data remain out of all reports. |
| Fixture matrix | Secure, vulnerable, unsupported/non-applicable, and false-positive/ambiguous fixtures or a documented equivalent where an external scanner’s output is mocked. |
| Validation | Frozen dependency sync, Ruff, full tests, `git diff --check`, safe fixture scan(s), package-data build verification if a manifest changes, and review of JSON/Markdown/SARIF redaction. |
| Publication | Documentation update, atomic commit, push, and a truthful passive check of workflow runs. Never claim remote CI success without evidence. |

## 5. Current delivery state

| Workstream | Status | Explicit limitation |
|---|---|---|
| Deterministic policy, exact waivers, reports, CI baseline | Implemented | No compliance certification, deployment power, or automatic remediation. |
| Repository/profile/requirements evidence, planning, catalogs, coverage | Implemented | Diagnostic only; requirement evidence is not proof of implementation. |
| Python/FastAPI controls | Implemented as bounded static checks and metadata-only dynamic-route review | No semantic authorization proof, whole-program data flow, effective-path derivation, runtime configuration, or exhaustive API security. |
| Next.js controls | Implemented as bounded static checks | Middleware/proxy is structural metadata only; local guard markers are not authorization proof. |
| Go controls and offline advisory snapshot | Implemented within a narrow boundary | No live advisory database, reachability, indirect dependency resolution, or broad Go assurance. |
| Existing external adapters | Implemented and opt-in | They are not standard protected-branch gates without an explicit policy choice and calibration. |
| Trivy Dockerfile/Containerfile/Terraform adapter | Implemented and opt-in | No real-binary air-gap calibration or protected-branch adoption is complete; no image, Compose, Kubernetes, Helm, plans, tfvars, module, runtime, or cloud-state coverage. [3] |
| 21-domain taxonomy | Implemented as domain vocabulary | Only the currently mapped real contracts have actual implementation coverage. |

## 6. Active roadmap — ordered milestones

### Milestone 0 — Complete Trivy calibration approval outside the repository

**Status:** static corpus and structural tests are ready; actual calibration is pending.

A human-approved, independently provisioned Trivy `0.74.0` binary must be used on a demonstrably egress-isolated runner. The calibration executes the checked-in static corpus one directory at a time and retains only Before Deploy’s normalized redacted report and execution metadata. It must record binary provenance, observed rule IDs, category/path/line mapping, errors, false positives, false negatives, suppression neutralization behavior, and the precise air-gap evidence.

| Required result | Non-goal |
|---|---|
| Review the secure, vulnerable, ambiguous, suppression, and unsupported cases against the fixed adapter invocation. | Do not install/download Trivy from a repository or CI workflow. |
| Confirm `NOT_APPLICABLE` for out-of-scope Compose/tfvars inputs without process start. | Do not promote this adapter to default or strict CI automatically. |
| Review only normalized redacted outputs. | Do not retain raw scanner logs, source snippets, URLs, causes, or resource IDs. |
| Make any protected-branch adoption a separate reviewed policy decision. | Do not claim image, runtime, cloud, or comprehensive IaC assurance. |

The resulting human approval record is external operational evidence. It does not change the adapter’s source contract or policy authority. [3]

### Milestone 1 — Completed documentation and contract hygiene

Canonical planning and registry documentation now reflects the registered, opt-in Trivy adapter, its staged Dockerfile/Containerfile/Terraform boundary, and the fixed applicability predicates. Documentation also states that coverage is diagnostic-only and cannot become an implicit policy gate.

**Delivered evidence:** documentation links resolve; capability/control counts are maintained against package manifests; no policy behavior, scanner configuration, or catalog placeholder was added.

### Milestone 2 — Completed bounded Go advisory expansion

`SEC-GO-VULN-001` now includes reviewed `GO-2020-0001` for exact direct root `github.com/gin-gonic/gin` declarations before `v1.6.0`, alongside the existing x/text boundary. The snapshot remains digest-pinned package data, uses static local parsing, and adds affected/fixed/indirect Gin fixtures. It did not add a live OSV/GitHub lookup, arbitrary semver-range engine, package download, Go tool invocation, or reachability analysis.

**Delivered evidence:** official Go-database review recorded; affected/fixed/indirect regression fixtures; refreshed digest; redaction tests; unchanged policy selection boundary.

### Milestone 3 — Completed Next.js Server Action precision increment

`SEC-NEXT-INLINE-ACTION-001` now covers exactly one formerly excluded shape: a named `async function` nested in a lexical block whose first executable statement is inline `use server`, followed by a direct `db`/`prisma` mutation with no preceding local guard marker. It has a separate implementation ID, capability, control contract, dedicated opt-in policy, and secure/vulnerable/page-only/excluded fixtures. It did not alter `SEC-NEXT-ACTION-001` or its historical finding fingerprints.

**Delivered boundary:** arrow actions, module-level/exported actions, directives after executable code, aliases, wrappers, helpers, page-level checks, proxy/middleware, ownership, tenancy, closures, and runtime reachability remain excluded; execution metadata remains non-authoritative.

### Milestone 4 — Completed Python SQL local-flow precision increment

`SEC-SAST-SQL-ALIAS-001` now covers one formerly excluded shape: a direct same-scope local name-to-name alias from an already unsafe SQL construction to a standalone `execute`/`executemany` sink. It has a separate implementation ID, capability, control contract, dedicated opt-in policy, and affected/parameterized/reassigned/excluded fixtures. It did not alter `SEC-SAST-001` or its historical finding fingerprints.

**Delivered boundary:** alias chains, branches, loops, `try`/`with`/`match` blocks, calls, imports, object attributes, subscripts, tuples, annotations, closures, globals, nonlocals, wrapped sinks, ORM behavior, parameter binding semantics, reachability, and runtime flow remain excluded. The next precision candidate must be a different one of these forms and receive its own separate contract.

### Milestone 5 — Completed FastAPI dynamic-router-prefix review

`SEC-API-001` v0.3.0 adds exactly one metadata-only route-review shape: a direct module-top-level simple-name assignment to `APIRouter(prefix=...)` where the prefix is not a literal slash-prefixed string, followed by a direct supported route decorator on that same name. It creates a deterministic `DYNAMIC_ROUTER_PREFIX` execution-metadata location with `REVIEW_REQUIRED`, not a finding, fingerprint, waiver target, coverage state, policy input, or release effect.

**Delivered boundary:** direct literal prefixes retain existing static-route behavior. The control does not resolve expressions or imports; infer aliases, factories, branch/loop/try/with/match assignments, annotations, multi-target/reassignment semantics, `include_router`, `mount`, nested routers, runtime registration, decorator aliases, effective paths, or FastAPI runtime behavior. Unit and default-policy integration fixtures cover the dynamic direct form, literal form, alias exclusion, zero findings, `PASS`, and redacted JSON/Markdown/SARIF reports.

### Milestone 6 — One additional language ecosystem, selected by evidence quality

Start one non-Python/non-JavaScript ecosystem only when a high-confidence bounded control can be specified without execution. The preferred order is determined by the availability of safe static evidence, not language popularity:

1. **PHP/Laravel**: a narrowly scoped configured Semgrep rule pack or exact Composer lock/manifests evidence, if a packaged ruleset can be reviewed without remote registry use.
2. **Rust**: one `Cargo.toml`/`Cargo.lock` integrity or static source pattern control without invoking Cargo.
3. **Java/Kotlin or C#**: one manifest/configuration or static source control with a precise parser boundary.

CodeQL is not a prerequisite and remains deferred while its build model conflicts with target-code and dependency-execution boundaries.

**Acceptance:** one language, one control family, one contract, one policy activation path, one fixture matrix. Do not mark the language generically “supported.”

### Milestone 7 — Ecosystem-specific dependency evidence

Add dependency capabilities one ecosystem at a time, each with a declared input, offline/packaged advisory evidence if vulnerabilities are evaluated, and no resolver invocation. Potential paths include Node lockfile integrity, Rust lock evidence, Composer lock evidence, or JVM lock/manifest presence. Each remains inside `DOMAIN-SUPPLY-CHAIN-001` but receives a unique contract and explicit limitations.

**Acceptance:** exact supported input formats; deterministic ordering; lock/manifests and advisory boundaries clearly distinguished; no registry request, installation, build, or source-reachability assertion.

### Milestone 8 — Infrastructure expansion, one artifact family at a time

The existing Trivy adapter must not silently broaden. Any new artifact family requires a new adapter contract or a carefully versioned expansion with distinct fixtures and calibration.

| Candidate | First permitted scope | Explicitly excluded initially |
|---|---|---|
| Docker Compose | Static YAML configuration only, staged independently after adapter design and calibration. | Image pull, service startup, network probing, secrets validity, runtime privileges. |
| Kubernetes manifests | Static manifest configuration only, independently staged. | Cluster access, admission behavior, live RBAC, workload execution. |
| Helm | Only a hermetic, fixed rendering/input model if one can be designed without target values/plugins/network. | Target chart scripts, remote dependencies, arbitrary values, cluster state. |
| CloudFormation | Static templates only with a strict parser/scanner boundary. | Account inspection, deployment changes, live IAM evaluation. |
| Terraform plans | Defer until a no-target-command/no-provider/no-state trust model is proven. | Running `terraform init`, `plan`, provider calls, external data resolution. |

**Acceptance:** no modification to existing Trivy Dockerfile/Terraform policy until the new family has its own calibrated data contract and explicit policy selection.

### Milestone 9 — Deterministic requirements-evidence expansion

Extend requirements signals one bounded phrase family at a time: authorization, webhooks, external URL fetching, file parsing, database usage, messaging, cloud integration, administration, multi-tenancy, AI/ML, or financial transactions. Store only a versioned signal ID, category, path, and first line — never arbitrary prose or an LLM interpretation.

**Acceptance:** false-positive corpus; non-implementation examples; explicit `DECLARED_REVIEW_REQUIRED` output; proof that requirements signals cannot select a scanner, create a finding, or alter the release decision.

### Milestone 10 — Control-level and domain-level coverage refinement

Continue coverage visibility using the existing semantic states. A domain may become `PARTIAL` when several implemented scoped contracts cover distinct sub-surfaces, but reports must state the individual contract boundaries. Do not introduce a global score or conflate the absence of an implementation with a secure result.

**Acceptance:** coverage changes are fully diagnostic; tests demonstrate no change to policy outcomes merely from catalog/coverage metadata; all report formats explain state and exclusions.

### Milestone 11 — Optional external/runtime evidence, separate architecture

Only after repository-only work is mature, design optional external evidence for cloud, Kubernetes, identity, API endpoint, container registry, artifact registry, or deployment manifest state. This is a new trust model, not an extension of a local repository scanner.

**Preconditions:** explicitly provisioned read-only identities; no production/deployment credentials in scan processes; separately approved connector/configuration model; scope and tenancy confinement; network and secret controls; evidence freshness/provenance; strict redaction; read-only behavior; fail-closed semantics; isolated policy profile.

**Non-goal:** the repository scanner must never gain unrestricted cloud access, deployment authority, or a claim that static source mirrors deployed state.

### Milestone 12 — Read-only advisory AI

Only after the preceding contracts, reports, redaction, and policy behavior are stable, a future advisory AI may receive normalized redacted JSON/Markdown/SARIF output and answer explanation-oriented questions. It may prioritize human review and suggest remediation for human approval.

It must not receive source secrets, raw scanner logs, policy write capability, waiver write capability, tool-selection ability, command execution, browser/session control, merge rights, deployment rights, or release-decision authority.

## 7. Long-term 21-domain posture

The roadmap maintains the 21 foundational domain vocabulary and its distinct extensions. A domain becomes public “coverage” only at the exact level its mapped controls support.

| Domain status category | Public interpretation |
|---|---|
| Taxonomy only / `UNAVAILABLE` | The domain is recognized, but no approved capability covers the observed surface. |
| `NOT_SELECTED` | A compatible approved capability exists, but the active policy did not select it. |
| `NOT_APPLICABLE` | The profile/evidence does not match the mapped capability’s reviewed boundary. |
| `DECLARED_REVIEW_REQUIRED` | Documentation indicates a possible surface; it is not implementation evidence or a vulnerability. |
| `PARTIAL` | One or more selected scoped contracts did not complete, or only defined sub-surfaces are covered. |
| `COVERED` | Selected scoped controls completed; this does not mean exhaustive security, production readiness, or compliance. |
| `ERROR` | A selected mapped capability failed; policy determines whether the configured error is release-blocking. |

## 8. Definition of done for the eventual 21-domain product

The product may truthfully say it **evaluates 21 domains** when each domain has a versioned definition, bounded activation evidence, explicit exclusions, visible unavailable/review semantics, and cataloged references. It may say a domain has **implemented coverage** only when at least one real reviewed control contract maps to it.

No individual control is complete unless it has a stable implementation ID, capability registration, contract, controlled policy selection, redacted normalized output, scope/exclusions, secure/vulnerable/unsupported/ambiguous fixture evidence, and validation. No external scanner is ready for protected-branch use unless it has a pin/provenance approach, isolation, timeout/output limits, strict errors, redaction, real-binary calibration evidence, and a separately approved policy adoption.

## 9. Operating rules

1. **One real capability at a time.** Do not combine a new language, scanner, package ecosystem, and policy rollout in one milestone.
2. **Implementation before metadata.** Never pre-register a future control/capability or make a catalog entry imply an analyzer exists.
3. **Policy before promotion.** A tool on `PATH` never matters unless the selected policy explicitly constructs its registered adapter.
4. **No target execution.** Repository-controlled scripts, builds, tool configs, rules, module fetches, providers, test commands, and runtime services remain untrusted data, not instructions.
5. **No hidden network.** Use local packaged evidence or separately provisioned tooling. Do not fall back from a failed offline scan to a networked scan.
6. **Privacy by normalization.** Capture only fields required for reproducible findings and waivers; discard raw upstream data immediately.
7. **Coverage is not a score or gate.** Keep diagnostic explanations separate from detection and release policy.
8. **No compliance inflation.** Do not claim SLSA attainment, certifications, exhaustive protection, production readiness, or comprehensive language support from partial controls.
9. **Truthful delivery reports.** State local validation outcomes and remote workflow results separately. “No run found” is not green CI.

## References

[1]: https://github.com/haytamAroui/befor-deploy-for-vibe-coder/blob/master/docs/ADAPTIVE_PLANNING_FOUNDATION.md "Before Deploy — Adaptive Planning Foundation"
[2]: https://github.com/haytamAroui/befor-deploy-for-vibe-coder/blob/master/docs/DECLARATIVE_CAPABILITY_REGISTRY.md "Before Deploy — Declarative Capability Registry"
[3]: https://github.com/haytamAroui/befor-deploy-for-vibe-coder/blob/master/docs/TRIVY_CONFIG_ADAPTER.md "Before Deploy — Isolated Trivy Configuration Adapter"
[4]: https://trivy.dev/docs/latest/advanced/air-gap/ "Trivy — Connectivity and Network Considerations"
[5]: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages "GitHub Docs — CodeQL for compiled languages"
