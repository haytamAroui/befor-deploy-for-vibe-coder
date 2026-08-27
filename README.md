# Before Deploy for Vibe Coder

**Before Deploy for Vibe Coder** is a deterministic pre-deployment security gate for multi-language repositories. It profiles bounded repository evidence, selects compatible controls, normalizes results, applies a versioned policy, and emits redacted reports for developers and CI systems.

> **The deterministic policy engine is the only release authority.** AI assistance is intentionally outside the gate: it may later explain a redacted finding or propose a patch, but it may not approve a release, change policy, access secrets, execute commands, or merge code.

## What it does today

The current release is a local and CI-ready Python CLI with deterministic adaptive project profiling. It supports self-contained native controls and a small set of opt-in isolated external adapters, including a staged Trivy configuration adapter for Dockerfile/Containerfile variants and Terraform `.tf` files. It records control health as well as findings, so an unavailable required scanner is an explicit `ERROR`, never a pass.

| Area | Current capability |
|---|---|
| **Repository evidence** | Deterministic inventory, repository digest, policy digest, Git revision when available, explicit scope limitations, and bounded repository/requirements evidence signals. |
| **Adaptive planning** | Local profile plus strict packaged capability and security-domain/control catalogs. The versioned `SecurityAnalysisPlan` records approved compatible controls, explicitly policy-configured adapters, the reviewed non-executable contract behind every selected implementation, catalog/policy provenance, coverage expectations, exclusions, and traceable evidence. |
| **Native controls** | High-confidence secret patterns, selected Python SQL interpolation including one local straight-line assignment flow, FastAPI static mutating-route authentication declarations plus dynamic-route review states, Python debug/CORS patterns, Next.js public-environment, session-cookie, static-CORS, and Server Action local-guard-marker checks, GitHub Actions hardening, dependency lockfile presence, an exact offline Go vulnerability snapshot check, and a release SBOM check. |
| **External adapters** | Optional Gitleaks directory scan, Python Semgrep local-rule scan, Go Gosec static analysis, Python dependency-vulnerability evidence, offline provenance verification, and a staged Trivy Dockerfile/Containerfile/Terraform configuration scan; each has bounded execution and redacted normalization. |
| **Policy** | Versioned YAML profiles, explicit block/waiver/warn dispositions, tightly scoped expiry-bound waivers, and fail-closed control errors. |
| **Reports** | Versioned JSON, Markdown, and SARIF 2.1.0 writers containing normalized findings, control health, adaptive profile, policy/catalog-bound security analysis plan, a non-executable domain/control taxonomy, and diagnostic coverage audit. |
| **CI behavior** | Machine-readable exit codes, a least-privilege frozen-`uv` CI gate, and a manual pinned external-scanner calibration workflow. |

## What it does not do

Before Deploy is **not** a compliance-certification service, a penetration-test replacement, a guarantee that a deployed system is secure, or an autonomous deployment tool. A green result means that the selected controls completed against the declared repository scope; it does not prove absence of vulnerabilities, operational misconfiguration, or regulatory compliance.

The tool now provides a **foundation** for Python dependency vulnerability evidence, offline GitHub artifact-attestation verification through a separate release profile, deterministic requirements-document evidence, and isolated static Trivy configuration evidence for selected Dockerfile/Containerfile and Terraform files. It does not make external tools a standard protected-branch release gate, scan container images, Docker Compose, Kubernetes, Helm, CloudFormation, Terraform plans or tfvars, scan non-Python package ecosystems for known vulnerabilities, verify runtime cloud configuration, infer that declared requirements are implemented, calculate coverage percentages, generate signed attestations in this private repository without confirmed eligibility, or perform automatic remediation.

## Adaptive project profiling

Every scan begins with a deterministic **Repository Evidence Collector** and **Adaptive Project Profiler**. They classify only bounded repository facts: file extensions, root manifests, lockfiles, fixed framework markers, selected infrastructure artifacts, and explicit requirements-document signals. A versioned **Security Analysis Plan** records the compatible approved controls and explicitly policy-configured adapters selected for that evidence; incompatible configured controls remain visible as `NOT_APPLICABLE` rather than being silently omitted.

| Detected technology | Current adaptive behavior |
|---|---|
| **Python / FastAPI** | Enables existing Python AST, configuration, FastAPI-route, dependency, and release-evidence capabilities where the selected policy includes them. Python SQL detection covers direct interpolation and one local straight-line variable assignment into an autonomous `execute`/`executemany` call; it does not trace branches, aliases, calls, imports, objects, or interprocedural flow. Dynamic FastAPI paths or `api_route` methods emit `REVIEW_REQUIRED` execution metadata only; they are not findings and do not change the gate. |
| **JavaScript / TypeScript / Next.js** | Retains generic controls, GitHub Actions checks, and lockfile evidence; when Next.js is detected, adds direct public-env, explicit session-cookie, static credentialed-CORS, and a narrow module-level Server Action direct-mutation/local-guard-marker check. `middleware`/`proxy` presence is emitted only as a structural execution fact, never as authorization evidence. |
| **Go** | Adds root-module `go.sum` presence when dependencies are declared, direct `tls.Config{InsecureSkipVerify: true}` detection, and an opt-in comparison of exact direct `go.mod` versions against two packaged reviewed offline vulnerability boundaries. The optional Gosec adapter supplies bounded static-analysis evidence only when the explicit external-adapters policy selects a preinstalled binary. |
| **Dockerfile / Containerfile / Terraform** | The separate Trivy profile scans only inventory-included Dockerfile/Containerfile variants and Terraform `.tf` files after copying them to an isolated temporary stage. It scans no container image, Compose, tfvars, plan, module, cloud state, runtime configuration, or generated/excluded artifact. |
| **Rust, Java, Kotlin, Ruby, PHP, C#** | Retains generic secrets/CI/provenance controls and reports an explicit language-specific coverage gap. |
| **Mixed-language repositories** | Detects each recognized language independently, retains compatible controls, and exposes all coverage gaps in JSON, Markdown, and SARIF reports. |

These deterministic components are **not an AI release authority**. They cannot mutate policy, create waivers, suppress findings, execute project code, deploy, merge, or access values beyond the bounded repository scan scope. The packaged capability registry is non-executable: its strict manifests cannot carry commands, URLs, executable paths, arbitrary scanner arguments, or policy overrides. Documentation signals create coverage expectations only; they never prove implementation or affect `PASS`, `BLOCK`, `WAIVER_REQUIRED`, or `ERROR`. A future advisory AI may read normalized redacted reports, but it will remain read-only and cannot change the gate decision.

For the detection catalog, control-selection rules, and advisory boundary, see [`docs/ADAPTIVE_PROJECT_PROFILING.md`](docs/ADAPTIVE_PROJECT_PROFILING.md). The Go reference pack, its adapter isolation, and its explicit exclusions are documented in [`docs/GO_REFERENCE_PACK.md`](docs/GO_REFERENCE_PACK.md); the offline dependency-vulnerability snapshot contract is in [`docs/GO_VULNERABILITY_SNAPSHOT.md`](docs/GO_VULNERABILITY_SNAPSHOT.md). The isolated Trivy configuration adapter, staging boundary, normalized schema, and fail-closed behavior are documented in [`docs/TRIVY_CONFIG_ADAPTER.md`](docs/TRIVY_CONFIG_ADAPTER.md). The Next.js Server Action/proxy boundary is in [`docs/NEXTJS_SERVER_ACTION_BOUNDARY.md`](docs/NEXTJS_SERVER_ACTION_BOUNDARY.md), the Python local SQL-flow boundary is in [`docs/PYTHON_LOCAL_SQL_FLOW.md`](docs/PYTHON_LOCAL_SQL_FLOW.md), and the FastAPI dynamic-route review boundary is in [`docs/FASTAPI_DYNAMIC_ROUTE_REVIEW.md`](docs/FASTAPI_DYNAMIC_ROUTE_REVIEW.md). For planning and evidence, see [`docs/ADAPTIVE_PLANNING_FOUNDATION.md`](docs/ADAPTIVE_PLANNING_FOUNDATION.md). For the capability-registry schema, provenance, and coverage-state semantics, see [`docs/DECLARATIVE_CAPABILITY_REGISTRY.md`](docs/DECLARATIVE_CAPABILITY_REGISTRY.md). For the non-executable domain taxonomy, mapped controls, unavailable domains, and standards-reference boundary, see [`docs/SECURITY_DOMAIN_CONTROL_CATALOG.md`](docs/SECURITY_DOMAIN_CONTROL_CATALOG.md).

## Quick start

### Prerequisites

Use a supported operating system with **Python 3.11 or later** and [uv](https://docs.astral.sh/uv/) installed. Git is optional but recommended because the scan manifest records the checked-out revision when it is available.

Clone the repository and create the locked development environment:

```bash
git clone https://github.com/haytamAroui/befor-deploy-for-vibe-coder.git
cd befor-deploy-for-vibe-coder
uv sync --frozen --all-extras
```

Run the default policy against the tool itself:

```bash
uv run before-deploy scan . \
  --policy rules/default-policy.yaml \
  --output-dir reports/self-scan
```

A successful run prints `Before Deploy: PASS` and writes the reports below. The `reports/` directory is ignored by Git, so the local evidence does not become an accidental source change.

### Scan another repository

From the **Before Deploy** repository root, point the CLI at the repository you want to evaluate. The policy lives in this repository and may reference its local Semgrep rule pack, so keep the policy path explicit.

```bash
TARGET_REPOSITORY="/absolute/path/to/my-service"

uv run before-deploy scan "$TARGET_REPOSITORY" \
  --policy rules/default-policy.yaml \
  --output-dir /tmp/before-deploy-my-service
```

The default profile is self-contained: it does not require Gitleaks or Semgrep to be installed. Use it first to establish baseline behavior and resolve native findings.

## Installation and everyday use

The current supported installation model is to run the CLI from a checked-out, locked copy of this repository. This keeps the policy, native rule behavior, and local Semgrep rule pack reviewable in source control.

| Task | Command |
|---|---|
| Create or refresh the reproducible environment | `uv sync --frozen --all-extras` |
| Display available CLI commands | `uv run before-deploy --help` |
| Display scan arguments | `uv run before-deploy scan --help` |
| Run the standard security gate | `uv run before-deploy scan /path/to/repo --policy rules/default-policy.yaml --output-dir /tmp/before-deploy-output` |
| Print JSON to standard output | Add `--format json` |
| Print Markdown to standard output | Add `--format markdown` |
| Print SARIF to standard output | Add `--format sarif` |
| Limit the maximum scanned file size | Add `--max-file-bytes 500000` |
| Load reviewed waivers | Add `--waivers /path/to/waivers.yaml` |

All output formats are written even when a different primary format is printed to the terminal. The `--format` flag changes standard output only.

## Understanding scan outcomes and exit codes

The CLI returns a stable exit code suitable for CI branch protection.

| Outcome | Exit code | Meaning | Required action |
|---|---:|---|---|
| `PASS` | `0` | Applicable required controls completed, with no unwaived blocking result. | Promotion may continue under this gate. |
| `NOT_EVALUATED` | `0` | No configured control applied to the selected scope. | Review the visible scope limitation; this is not a security pass. |
| `BLOCK` | `10` | At least one applicable policy-blocking finding remains unwaived. | Remediate the issue, then scan again. |
| `WAIVER_REQUIRED` | `11` | A policy-defined risk requires an explicit, unexpired waiver. | Obtain a narrowly scoped security waiver or remediate. |
| `ERROR` | `20` | A required tool failed, inputs are invalid, a report is malformed, or required evidence is unavailable. | Fix the scan/tool configuration. Do not treat the result as clean. |

A command that blocks is expected to return a nonzero code. For example, this fixture is intentionally unsafe and should return `10`:

```bash
uv run before-deploy scan fixtures/vulnerable_fastapi_nextjs \
  --policy rules/default-policy.yaml \
  --output-dir /tmp/before-deploy-vulnerable
```

The secure fixture is expected to pass:

```bash
uv run before-deploy scan fixtures/secure_fastapi_nextjs \
  --policy rules/default-policy.yaml \
  --output-dir /tmp/before-deploy-secure
```

## Reports and evidence

Every completed CLI scan writes three redacted artifacts to `--output-dir`. The report writers are part of the versioned package source and have been verified from a fresh repository checkout.

| File | Intended use | Contents |
|---|---|---|
| `report.json` | Automation and future control-plane integrations. | Full normalized scan result, manifest, adaptive project profile, evidence identifiers, policy/catalog-bound security analysis plan including selected control-contract provenance, diagnostic coverage audit, control executions, policy decision, findings, and waivers. |
| `report.md` | Pull-request and release review. | Gate rationale, adaptive technology profile, approved plan selections with implementation/policy/catalog provenance and selected contract scope/exclusions, coverage expectations/audit, explicit exclusions, execution status, grouped findings, remediation guidance, waiver list, and limitations. |
| `report.sarif` | Code-scanning integrations. | SARIF 2.1.0-compatible rule/location information plus redacted profile, plan, and coverage-audit properties. |

The scan manifest binds reports to the repository digest, policy digest, policy name, scan timestamps, bounded file count, and relevant Git revision. Before Deploy deliberately does **not** print raw secret values in its own normalized reports. If a secret detector reports a potential credential, rotate it through the relevant issuer and inspect access logs according to your incident procedure.

## Policies

Policies are human-reviewable YAML files under `rules/`. A policy explicitly selects controls, their required status, and their disposition. A tool that happens to be on `PATH` never affects a release unless the selected policy enables its control.

| Profile | Use it when | Main behavior |
|---|---|---|
| `rules/default-policy.yaml` | Local development and baseline assessment. | Runs the validated native controls. It is the recommended starting profile. |
| `rules/strict-ci-policy.yaml` | Protected-branch CI. | Runs the native pre-deployment controls with every configured control required and fail-closed error behavior. |
| `rules/external-adapters-policy.yaml` | A team has installed and calibrated the pinned Gitleaks, Semgrep, and Gosec binaries. | Replaces bootstrap secret/SAST controls with required external adapters. Gosec is explicitly selected only for detected root Go modules; it remains `NOT_APPLICABLE` outside that scope. |
| `rules/go-vulnerability-snapshot-policy.yaml` | A Go module has a reviewed need for the packaged snapshot’s exact advisory boundary. | Runs native Go module/TLS checks plus `SEC-GO-VULN-001`; no scanner, Go tool, network request, or target code execution occurs. |
| `rules/trivy-config-policy.yaml` | A team has independently provisioned the pinned Trivy binary and wants the bounded configuration evidence. | Runs only `SEC-TRIVY-CONFIG-001`, which stages eligible Dockerfile/Containerfile and Terraform `.tf` files, uses fixed offline misconfiguration-only arguments, and fails closed on binary/version/report/staging errors. |
| `rules/strict-policy.yaml` | Release-evidence experimentation. | Includes the SBOM presence control. It remains separate for teams that are not yet supplying signed artifacts. |
| `rules/release-evidence-policy.yaml` | A release candidate with exported Python dependencies, an SBOM, a local artifact, and a downloaded GitHub attestation bundle. | Requires core controls plus pip-audit vulnerability evidence, SBOM presence, and offline signed-attestation verification. |

A minimal policy has this shape:

```yaml
schema_version: 1
profile: example
public_fastapi_routes:
  - path: /healthz
    methods: [GET]
controls:
  SEC-SECRET-001:
    required: true
    disposition: BLOCK
```

Each control can use one of three finding dispositions: `BLOCK`, `WAIVER_REQUIRED`, or `WARN`. Required-control execution errors remain errors; a policy must never convert a scanner failure into a pass.

### FastAPI public-route allowlist

`SEC-API-001` requires a visible `Depends(...)` or `Security(...)` declaration for mutating FastAPI routes unless the exact route and method are in `public_fastapi_routes`. Keep this allowlist small, explicit, and reviewed. For example, a health endpoint may be public, but an unauthenticated mutating webhook should be justified by its own authentication and signature-validation control rather than silently allowlisted.

### Using a waiver

Waivers are intentionally narrow. A valid record must match the exact finding fingerprint, rule ID, and repository digest; it must also name an approver, justification, compensating controls, and future expiry. A changed source tree changes the repository digest and invalidates the waiver.

First run the scan and obtain the finding fingerprint and repository digest from `report.json`. Then create a reviewed waiver file such as:

```yaml
schema_version: 1
waivers:
  - id: security-2026-001
    finding_fingerprint: "exact-fingerprint-from-report"
    rule_id: "SEC-DEP-001"
    repository_digest: "exact-repository-digest-from-report"
    approved_by: "security-owner@example.com"
    justification: "A vendor patch is scheduled for the next approved release window."
    compensating_controls: "The affected service is isolated and access is restricted."
    expires_at: "2026-12-31T23:59:59Z"
```

Run the same scan with the waiver file:

```bash
uv run before-deploy scan /path/to/repository \
  --policy rules/default-policy.yaml \
  --waivers /path/to/waivers.yaml \
  --output-dir /tmp/before-deploy-waived
```

Do not use waivers for missing binaries, invalid policy files, malformed scanner output, or any other control `ERROR`. Fix the execution problem instead.

## Optional external scanner profile

The external profile is opt-in because third-party scanner output must be calibrated before it becomes a release authority. It activates isolated adapters for **Gitleaks 8.30.1**, **Gosec v2.29.0** (only for detected root Go modules), and **Semgrep 1.175.0**.

### Install and verify the scanners

Install Gitleaks, Gosec, and Semgrep through your approved software-distribution process. Verify the executable path and version before using the profile. Do not install scanners from target repositories. For Semgrep, an isolated uv tool installation can be used:

```bash
uv tool install "semgrep==1.175.0"
semgrep --version

gitleaks version
gosec --version
```

The policy declares expected versions for traceability. Your team should pin downloaded scanner artifacts or container digests through its own dependency-management process and ensure `gitleaks`, `gosec`, and `semgrep` are available on `PATH` in the CI runner. The Gosec adapter uses only fixed arguments, ignores inline suppressions, disables module-network resolution with `GOPROXY=off`, and uses read-only module behavior; missing local dependencies are an explicit `ERROR`, not a download attempt.

### Run the external profile

```bash
uv run before-deploy scan /path/to/repository \
  --policy rules/external-adapters-policy.yaml \
  --output-dir /tmp/before-deploy-external
```

The adapters use fixed argument lists, a minimal child-process environment, temporary reports outside the scanned repository, bounded report size, and timeouts. They do not run target-supplied commands, enable Gosec AI-fix mode, enable Semgrep autofix, allow Semgrep local builds, use remote Semgrep registry rules, download Go modules, or retain raw Gitleaks secrets or Gosec source/details in Before Deploy reports.

If either required binary is missing, times out, produces invalid JSON, or reports an internal scan error, the outcome is `ERROR` with exit code `20`. This is intentional fail-closed behavior.

> Treat external scanner rules and configuration as security-sensitive source code. Review changes through pull requests, pin tool versions, and test rule changes against the secure and vulnerable fixtures before enabling them on protected branches.

## Release-evidence verification

The `release-evidence-policy.yaml` profile is intentionally **not** a general development scan. It is for a release-candidate directory that contains the declared artifact and a downloaded GitHub attestation bundle. It also requires the explicitly versioned `uv`, `pip-audit`, and `gh` executables on `PATH`.

```bash
uv run before-deploy scan /path/to/release-candidate \
  --policy rules/release-evidence-policy.yaml \
  --output-dir /tmp/before-deploy-release-evidence
```

The profile audits a locked Python dependency set, requires a CycloneDX SBOM, and verifies the local artifact against the expected GitHub repository and signer-workflow identity. Missing tools, a missing lock/SBOM/artifact/bundle, an unverifiable attestation, or malformed evidence returns `ERROR` with exit code `20`; this is expected fail-closed behavior. The detailed contract and threat boundary are in [`docs/DEPENDENCY_PROVENANCE_MILESTONE.md`](docs/DEPENDENCY_PROVENANCE_MILESTONE.md); the practical calibration, artifact-preparation, and conditional-attestation procedures are in [`docs/RELEASE_OPERATIONS.md`](docs/RELEASE_OPERATIONS.md).

## Continuous integration

The repository contains a hardened example workflow at `.github/workflows/ci.yml`. It uses read-only default permissions, a pinned Python setup action, a full-SHA-pinned uv setup action, `uv sync --frozen --all-extras`, linting, tests, a **strict-CI-policy** self-scan, and redacted report artifact retention.

To adopt the same pattern in another repository, vendor or package Before Deploy through your approved release process, then use a protected-branch job that runs the CLI and preserves the exit code. The gate must run in CI; local hooks provide convenience but can be bypassed.

```yaml
permissions:
  contents: read

jobs:
  security-gate:
    runs-on: ubuntu-24.04
    steps:
      - name: Check out source
        uses: actions/checkout@<full-verified-commit-sha>
      - name: Run Before Deploy gate
        run: >-
          uv run before-deploy scan .
          --policy /approved/path/default-policy.yaml
          --output-dir reports
```

Pin every third-party action to a verified full commit SHA. Do not use `pull_request_target` for jobs that check out or execute pull-request-controlled code, and do not grant `write-all` permissions to a scan job.

## Control coverage and limits

| Control | Default profile | Evidence boundary |
|---|---|---|
| `SEC-SECRET-001` | Enabled | Narrow native patterns in bounded working-tree text files; no Git-history scan. |
| `SEC-SAST-001` | Enabled | Python AST patterns for selected raw SQL interpolation directly into execute calls or through one local straight-line name assignment. It excludes branches, aliases, calls, imports, objects, closures, and interprocedural flow. |
| `SEC-API-001` | Enabled | Static FastAPI route decorators and visible `Depends`/`Security` declarations; not semantic proof of authorization. Dynamic paths or `api_route` methods produce `REVIEW_REQUIRED` execution metadata only, never a finding or gate change. |
| `SEC-CONFIG-001` | Enabled | Explicit debug declarations in Python and selected configuration files; not effective cloud runtime state. |
| `SEC-CONFIG-002` | Enabled | Credentialed wildcard CORS patterns in common FastAPI/config forms. |
| `SEC-NEXT-ENV-001` | Enabled when Next.js is detected | Direct `NEXT_PUBLIC_` references whose names clearly indicate a secret/private/session value; no computed-access analysis. |
| `SEC-NEXT-COOKIE-001` | Enabled when Next.js is detected | Explicit unsafe options on statically named session/auth/token cookies; no custom-wrapper or missing-option inference. |
| `SEC-NEXT-CORS-001` | Enabled when Next.js is detected | Static `next.config.*` header arrays combining wildcard origin and credentials; no middleware/proxy/runtime analysis. |
| `SEC-NEXT-ACTION-001` | Enabled when Next.js is detected | Module-level `use server` exported async functions with a direct `db`/`prisma` mutation before any recognized local guard marker. It does not prove authorization, ownership, proxy/middleware coverage, imports, closures, aliases, or runtime dataflow. |
| `SEC-CICD-001` | Enabled when workflows are present | Selected GitHub Actions trigger, permission, and action-pin checks. |
| `SEC-DEP-001` | Enabled | Supported Python/Node manifest and lockfile presence; not vulnerability analysis yet. |
| `SEC-GO-VULN-001` | `go-vulnerability-snapshot-policy.yaml` only | Exact direct root `go.mod` versions against two packaged reviewed advisory boundaries. It excludes indirect dependencies, reachability, `replace` directives, live-database freshness, remediation, and all network/tool execution. |
| `SEC-SECRET-GITLEAKS-001` | External profile | Gitleaks directory-scan findings, normalized without the raw secret. |
| `SEC-SAST-SEMGREP-001` | External profile | Checked-in local Semgrep rule findings, normalized without source excerpts. |
| `SEC-TRIVY-CONFIG-001` | `trivy-config-policy.yaml` only | Preinstalled Trivy 0.74.0 configuration findings from an isolated staged copy of inventory-included Dockerfile/Containerfile variants and Terraform `.tf` files. It uses fixed offline misconfiguration-only arguments, neutralizes inline Trivy ignores, ignores target `.trivyignore`, and retains only rule ID, severity, artifact category, relative path, and line. |
| `SEC-DEP-VULN-001` | Release-evidence profile | pip-audit JSON evidence against a declared Python lock/requirements input; it detects known advisories, not exploitability or non-Python packages. |
| `SEC-RELEASE-001` | Strict and release-evidence profiles | Presence and basic parseability of a CycloneDX JSON SBOM; not provenance validation. |
| `SEC-PROVENANCE-001` | Release-evidence profile | Offline `gh attestation verify` bundle verification with expected repository and signer workflow; it does not claim a generic SLSA level. |

Read the detailed control boundary and false-positive process in [`docs/CONTROL_CATALOG.md`](docs/CONTROL_CATALOG.md). The versioned domain-to-control mapping and explicit unavailable-domain posture are in [`docs/SECURITY_DOMAIN_CONTROL_CATALOG.md`](docs/SECURITY_DOMAIN_CONTROL_CATALOG.md). The Trivy staging/normalization boundary is in [`docs/TRIVY_CONFIG_ADAPTER.md`](docs/TRIVY_CONFIG_ADAPTER.md), while its non-executing secure/vulnerable/ambiguous/suppression/unsupported calibration corpus and future air-gap approval procedure are in [`fixtures/trivy_config_calibration/README.md`](fixtures/trivy_config_calibration/README.md). The dependency and provenance evidence contract is in [`docs/DEPENDENCY_PROVENANCE_MILESTONE.md`](docs/DEPENDENCY_PROVENANCE_MILESTONE.md).

## Repository structure

```text
src/before_deploy/       # Deterministic kernel, adaptive profiler, controls, adapters, and report writers
tests/                   # Unit, integration, fake-tool isolation, and profile-detection tests
rules/                   # Versioned policy profiles and local Semgrep rules
docs/                    # Architecture, capability contracts, release procedures, and control catalog
fixtures/                # Secure/vulnerable application fixtures plus static Trivy calibration corpus; no fixture application code is executed
.github/workflows/       # Hardened CI and manual external-scanner calibration
scripts/                 # Deterministic release-artifact and SBOM preparation
uv.lock                  # Reproducible development dependency lock
```

## Development and verification

Run the same checks used by repository CI:

```bash
uv sync --frozen --all-extras
uv run ruff check src tests scripts
uv run pytest
uv run before-deploy scan . \
  --policy rules/default-policy.yaml \
  --output-dir reports/self-scan
```

The fake-tool tests exercise Gitleaks/Semgrep/Gosec/Trivy normalization, secret redaction, fixed isolation flags, staged-input containment, target suppression neutralization, timeouts, missing binaries, malformed reports, version mismatches, and fail-closed paths without requiring live scanner binaries or real credentials. The checked-in Trivy calibration corpus adds secure, vulnerable, ambiguous, suppression, and unsupported static inputs; its tests verify scope and staging only, not a real scanner verdict.

## Security principles

The project follows least privilege, isolated execution, explicit policy, fail-closed release behavior for required controls, immutable rule and tool versions, redacted evidence, bounded waivers, and developer-reviewed remediation. All repository content, scanner output, and future AI inputs are treated as untrusted data.

## Status and next steps

The deterministic kernel, repository evidence collector, adaptive project profiler, strict declarative capability registry, non-executable security domain/control catalog, versioned security analysis planner, diagnostic coverage auditor, report writers, isolated external adapters, dependency/provenance evidence foundation, manual scanner calibration workflow, release-evidence preparation script, Next.js/TypeScript static controls including one bounded Server Action local-guard-marker check, a bounded Python local SQL-flow extension, FastAPI dynamic-route review metadata, the first bounded offline Go dependency-vulnerability snapshot, and one bounded staged Trivy configuration adapter are implemented and tested locally. A static secure/vulnerable/ambiguous/suppression/unsupported Trivy fixture corpus and air-gap calibration procedure are now also present, but no real Trivy calibration, network-isolation attestation, or protected-branch adoption has been performed. The domain catalog exposes twenty-one foundational security domains plus nine explicit extensions, while mapping only the controls actually implemented; unmapped domains remain visibly unavailable rather than silently treated as covered. It is not a compliance framework, a security score, or a certification. The Trivy adapter is separate from the default and strict-CI policies and does not establish container-image, runtime, cloud, or comprehensive IaC assurance. The next engineering priorities are human-reviewed air-gap calibration of this adapter, then further one-control-at-a-time language expansion; only later comes tightly bounded read-only AI assistance.

For the design rationale and phased roadmap, see [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) and [`docs/DEEP_ANALYSIS_AND_BUILD_BLUEPRINT.md`](docs/DEEP_ANALYSIS_AND_BUILD_BLUEPRINT.md).
