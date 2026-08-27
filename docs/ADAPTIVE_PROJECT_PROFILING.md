# Adaptive Project Profiling Contract

**Status:** Implemented deterministic component
**Component name:** **Adaptive Project Profiler**
**Implementation:** Deterministic, local repository profiling; no LLM, remote service, background process, or autonomous code modification.

> **Authority boundary:** The Adaptive Project Profiler discovers repository technology signals and records compatibility. The Repository Evidence Collector, Security Analysis Planner, and Coverage Auditor only describe bounded evidence and approved selections. None can change a policy, create a waiver, suppress a finding, alter a control result, generate a release decision, execute project code, or access raw values beyond the bounded source files already in scan scope.

## 1. Purpose

Before Deploy needs to scan mixed-language repositories honestly. The profiler determines what technologies are visible in the bounded inventory and maps those signals to controls that can produce meaningful evidence. This avoids running a Python AST control against a Go service while making the resulting coverage limits explicit.

The profiler is deterministic because language/framework classification is based on an ordered, versioned catalog of file extensions, root manifests, and bounded text markers. It does not infer meaning from arbitrary source text and does not call an AI model. The adjacent planning foundation turns the profile plus bounded evidence into an immutable Security Analysis Plan; see [`ADAPTIVE_PLANNING_FOUNDATION.md`](ADAPTIVE_PLANNING_FOUNDATION.md).

## 2. Project profile schema

| Field | Meaning | Example |
|---|---|---|
| `languages` | Sorted language identifiers supported by direct file-extension or manifest evidence. | `("Python", "TypeScript")` |
| `frameworks` | Sorted framework identifiers backed by a manifest or source marker. | `("FastAPI", "Next.js")` |
| `package_managers` | Lock/manifests observed for supported package ecosystems. | `("npm", "uv")` |
| `signals` | Redaction-safe marker paths/counts supporting classification. No source contents. | `{"manifest:pyproject.toml": "1", "extension:.py": "8"}` |
| `coverage_gaps` | Explicit control coverage limitations inferred from the profile. | `("No language-specific controls are available for Java.",)` |

A profile signal is evidence of repository makeup, not a claim that an application is secure, deployable, or even executable.

## 3. Initial detection catalog

| Technology | Deterministic signals | Initial control coverage |
|---|---|---|
| Python | `.py`, `pyproject.toml`, `requirements*.txt`, `uv.lock` | Native secret/SAST/config checks; FastAPI static route checks and dynamic-route review metadata when imported; pip-audit release evidence. |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.js`, `.jsx`, `package.json`, lockfiles | Cross-language secrets, CI, and lockfile evidence; generic TypeScript semantics remain outside the current scope. |
| Go | `.go`, `go.mod`, `go.sum` | Root-module `go.sum` presence when dependencies are declared, direct `tls.Config{InsecureSkipVerify: true}` detection, one opt-in offline version snapshot, and an opt-in isolated Gosec adapter. Framework/dataflow/live-database/runtime analysis remains an explicit gap. |
| Rust | `.rs`, `Cargo.toml` | Cross-language secrets and CI checks; coverage gap reports absence of Rust-specific SAST/dependency-vulnerability adapter. |
| Java / Kotlin | `.java`, `.kt`, `pom.xml`, `build.gradle*` | Cross-language secrets and CI checks; coverage gap reports absence of JVM-specific adapters. |
| Ruby | `.rb`, `Gemfile` | Cross-language secrets and CI checks; coverage gap reports absence of Ruby-specific adapters. |
| PHP | `.php`, `composer.json` | Cross-language secrets and CI checks; coverage gap reports absence of PHP-specific adapters. |
| C# | `.cs`, `*.csproj` | Cross-language secrets and CI checks; coverage gap reports absence of .NET-specific adapters. |

Framework signals include FastAPI, Django, Flask, Next.js, Express, NestJS, Spring, Rails, Laravel, and ASP.NET Core. FastAPI has static mutating-route dependency declarations plus non-decision dynamic-route review metadata. Next.js has narrow direct public-environment, session-cookie, static credentialed-CORS, and Server Action local-guard-marker controls. Other detected frameworks remain visible coverage gaps unless a dedicated control is stated.

## 4. Versioned capability catalog

The code maintains a fixed capability catalog. Each entry maps one control identifier to the languages/frameworks it can evaluate. A control is selected when its applicability condition is satisfied:

| Control family | Applicability rule |
|---|---|
| Secrets / Gitleaks / provenance | Applicable to every repository with scan scope, regardless of language. |
| GitHub Actions | Applicable only when a GitHub workflow file is visible. |
| Lockfile evidence | Applicable to detected Python or Node/TypeScript/JavaScript dependency ecosystems. |
| Go module integrity / direct TLS verification | Applicable only to a detected root Go module; module-sum presence and direct `tls.Config` literals only. |
| Gosec adapter | Applicable only to a detected root Go module and only when an explicit external policy configures a preinstalled binary. |
| Python direct/local SQL, separately opt-in one-alias SQL, production configuration, and pip-audit | Applicable only to detected Python repositories; each SQL contract has a separate bounded scope. |
| FastAPI route auth and dynamic review | Applicable only when FastAPI is detected. Static mutation routes may create ordinary findings; dynamic path/method structures create execution metadata only. |
| Local Semgrep adapter | Applicable only to detected Python because the initial checked-in rule pack is Python-only. |
| Next.js public-env, session-cookie, static CORS, module-level Server Action, and named-inline Server Action checks | Applicable only when Next.js is detected; each control has a separate direct/static lexical scope. |
| SBOM presence | Applicable to release profiles that declare the control, regardless of language. |

When a policy selects a control but the profile identifies it as incompatible, the orchestrator records an explicit `NOT_APPLICABLE` execution containing the adaptation reason. It does **not** silently omit that control. Required controls are still errors when they are missing because of a construction/configuration fault, not when deterministic compatibility records a legitimate non-applicability decision.

## 5. Coverage-gap reporting

Coverage gaps, Security Analysis Plans, and Coverage Audits are deterministic diagnostics, not security findings and not gate overrides. JSON, Markdown, and SARIF reports expose the selected approved capabilities, explicit exclusions, and `COVERED`, `PARTIAL`, `UNAVAILABLE`, `NOT_SELECTED`, `NOT_APPLICABLE`, `DECLARED_REVIEW_REQUIRED`, or `ERROR` coverage states. A future policy may explicitly select a reviewed control, but coverage states themselves cannot require a waiver or change a release outcome.

## 6. Advisory-agent boundary

A future read-only advisory agent may consume only the normalized project profile, redacted scan reports, selected control IDs, and stated coverage gaps. It may explain coverage or recommend an approved rule-pack installation. It may not inspect raw secrets, set control applicability, revise the capability catalog, change policy, create waivers, call deployment tools, or affect the release decision.

## 7. Acceptance criteria

| Scenario | Required behavior |
|---|---|
| FastAPI/Python repository | Detect Python and FastAPI; run selected Python/FastAPI-compatible controls, expose the separate opt-in one-alias SQL control, and report no Python coverage gap. |
| Next.js repository | Detect TypeScript/JavaScript and Next.js; run compatible cross-language controls, narrow static controls, and separately selected module-level and named-inline Server Action local-guard-marker checks; report deferred proxy/middleware, arrow-action, semantic authorization, and data-boundary coverage. |
| Go repository | Detect Go and root-module evidence; run selected module/TLS controls, expose the separately opt-in offline snapshot control, and report Gosec-backed injection, SSRF, and path-traversal coverage as `NOT_SELECTED` until an explicit adapter policy selects it. |
| Rust/Java mixed repository | Detect each language deterministically; retain generic checks; record language-specific coverage gaps. |
| Policy includes a Python-only control for a Go-only repository | Record `NOT_APPLICABLE` with a visible reason rather than silently dropping the control. |
| Unknown files or no recognized technology | Preserve generic controls and report that no language-specific catalog match was found. |
| Any repository | The policy engine remains the sole authority for `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, and `NOT_EVALUATED`. |
