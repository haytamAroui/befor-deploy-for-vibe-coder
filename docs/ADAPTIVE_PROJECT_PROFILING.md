# Adaptive Project Profiling Contract

**Status:** Approved for implementation
**Component name:** **Adaptive Project Agent**
**Implementation:** Deterministic, local repository profiling; no LLM, remote service, background process, or autonomous code modification.

> **Authority boundary:** The Adaptive Project Agent discovers repository technology signals and selects compatible controls. It does not change a policy, create a waiver, suppress a finding, alter a control result, generate a release decision, execute project code, or access secrets beyond the bounded source files already in scan scope.

## 1. Purpose

Before Deploy needs to scan mixed-language repositories honestly. The agent determines what technologies are visible in the bounded inventory and maps those signals to the controls that can produce meaningful evidence. This avoids running a Python AST control against a Go service while making the resulting coverage limits explicit.

The agent is deterministic because language/framework classification is based on an ordered, versioned catalog of file extensions, root manifests, and bounded text markers. It does not infer meaning from arbitrary source text and does not call an AI model.

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
| Python | `.py`, `pyproject.toml`, `requirements*.txt`, `uv.lock` | Native secret/SAST/config checks; FastAPI support when imported; pip-audit release evidence. |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.js`, `.jsx`, `package.json`, lockfiles | Cross-language secrets, CI, lockfile evidence; Next.js detected for visible reporting only. |
| Go | `.go`, `go.mod` | Cross-language secrets and CI checks; coverage gap reports absence of Go-specific SAST/dependency-vulnerability adapter. |
| Rust | `.rs`, `Cargo.toml` | Cross-language secrets and CI checks; coverage gap reports absence of Rust-specific SAST/dependency-vulnerability adapter. |
| Java / Kotlin | `.java`, `.kt`, `pom.xml`, `build.gradle*` | Cross-language secrets and CI checks; coverage gap reports absence of JVM-specific adapters. |
| Ruby | `.rb`, `Gemfile` | Cross-language secrets and CI checks; coverage gap reports absence of Ruby-specific adapters. |
| PHP | `.php`, `composer.json` | Cross-language secrets and CI checks; coverage gap reports absence of PHP-specific adapters. |
| C# | `.cs`, `*.csproj` | Cross-language secrets and CI checks; coverage gap reports absence of .NET-specific adapters. |

Framework signals initially include FastAPI, Django, Flask, Next.js, Express, NestJS, Spring, Rails, Laravel, and ASP.NET Core. A framework may be detected without a dedicated control; this is intentionally visible as a coverage gap rather than an unsupported promise.

## 4. Versioned capability catalog

The code maintains a fixed capability catalog. Each entry maps one control identifier to the languages/frameworks it can evaluate. A control is selected when its applicability condition is satisfied:

| Control family | Applicability rule |
|---|---|
| Secrets / Gitleaks / provenance | Applicable to every repository with scan scope, regardless of language. |
| GitHub Actions | Applicable only when a GitHub workflow file is visible. |
| Lockfile evidence | Applicable to detected Python or Node/TypeScript/JavaScript dependency ecosystems. |
| Python SQL / production configuration / pip-audit | Applicable only to detected Python repositories. |
| FastAPI route auth | Applicable only when FastAPI is detected. |
| Local Semgrep adapter | Applicable only to detected Python because the initial checked-in rule pack is Python-only. |
| SBOM presence | Applicable to release profiles that declare the control, regardless of language. |

When a policy selects a control but the profile identifies it as incompatible, the orchestrator records an explicit `NOT_APPLICABLE` execution containing the adaptation reason. It does **not** silently omit that control. Required controls are still errors when they are missing because of a construction/configuration fault, not when the agent records a legitimate non-applicability decision.

## 5. Coverage-gap reporting

Coverage gaps are deterministic diagnostics, not security findings and not gate overrides in this milestone. They are emitted in JSON and Markdown reports so a team can see, for example, that a Go service currently receives only secrets and CI checks. A future policy may make named coverage gaps require a waiver, but that would be a separate, explicit policy decision.

## 6. Advisory-agent boundary

A future read-only advisory agent may consume only the normalized project profile, redacted scan reports, selected control IDs, and stated coverage gaps. It may explain coverage or recommend an approved rule-pack installation. It may not inspect raw secrets, set control applicability, revise the capability catalog, change policy, create waivers, call deployment tools, or affect the release decision.

## 7. Acceptance criteria

| Scenario | Required behavior |
|---|---|
| FastAPI/Python repository | Detect Python and FastAPI; run Python/FastAPI-compatible controls; report no Python coverage gap. |
| Next.js repository | Detect TypeScript/JavaScript and Next.js; run compatible cross-language controls; report that Next.js-specific controls are not yet provided. |
| Go/Rust/Java mixed repository | Detect each language deterministically; retain generic checks; record language-specific coverage gaps. |
| Policy includes a Python-only control for a Go-only repository | Record `NOT_APPLICABLE` with a visible reason rather than silently dropping the control. |
| Unknown files or no recognized technology | Preserve generic controls and report that no language-specific catalog match was found. |
| Any repository | The policy engine remains the sole authority for `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, and `NOT_EVALUATED`. |
