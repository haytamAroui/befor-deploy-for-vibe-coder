# Before Deploy for Vibe Coder

**Before Deploy for Vibe Coder** is a deterministic pre-deployment security gate for FastAPI and Next.js repositories. It collects bounded repository evidence, runs explicit controls, normalizes the results, applies a versioned policy, and emits redacted reports for developers and CI systems.

> **The deterministic policy engine is the only release authority.** AI assistance is intentionally outside the gate: it may later explain a redacted finding or propose a patch, but it may not approve a release, change policy, access secrets, execute commands, or merge code.

## What it does today

The current release is a local and CI-ready Python CLI. It supports self-contained native controls and an opt-in foundation for isolated Gitleaks and Semgrep adapters. It records control health as well as findings, so an unavailable required scanner is an explicit `ERROR`, never a pass.

| Area | Current capability |
|---|---|
| **Repository evidence** | Deterministic inventory, repository digest, policy digest, Git revision when available, and scan limitations. |
| **Native controls** | High-confidence secret patterns, selected SQL interpolation, FastAPI mutating-route authentication declarations, debug settings, unsafe credentialed CORS, GitHub Actions hardening, dependency lockfile presence, and a release SBOM check. |
| **External adapters** | Optional Gitleaks directory scan and Semgrep local-rule scan, with bounded execution and redacted normalization. |
| **Policy** | Versioned YAML profiles, explicit block/waiver/warn dispositions, and tightly scoped expiry-bound waivers. |
| **Reports** | Terminal summary, normalized JSON, Markdown review report, and SARIF 2.1.0-compatible output. |
| **CI behavior** | Machine-readable exit codes and a least-privilege GitHub Actions workflow using a frozen `uv` environment. |

## What it does not do

Before Deploy is **not** a compliance-certification service, a penetration-test replacement, a guarantee that a deployed system is secure, or an autonomous deployment tool. A green result means that the selected controls completed against the declared repository scope; it does not prove absence of vulnerabilities, operational misconfiguration, or regulatory compliance.

The tool now provides a **foundation** for Python dependency vulnerability evidence and offline GitHub artifact-attestation verification through a separate release profile. It does not yet install/calibrate those external tools in project CI, scan non-Python package ecosystems, verify runtime cloud configuration, generate artifacts/attestations, or perform automatic remediation.

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
TARGET_REPOSITORY="/absolute/path/to/my-fastapi-service"

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

Every completed CLI scan writes three redacted artifacts to `--output-dir`.

| File | Intended use | Contents |
|---|---|---|
| `report.json` | Automation and future control-plane integrations. | Full normalized scan result, manifest, control executions, policy decision, findings, and waivers. |
| `report.md` | Pull-request and release review. | Gate rationale, execution status, grouped findings, remediation guidance, waiver list, and limitations. |
| `report.sarif` | Code-scanning integrations. | SARIF 2.1.0-compatible rule and location information. |

The scan manifest binds reports to the repository digest, policy digest, policy name, scan timestamps, bounded file count, and relevant Git revision. Before Deploy deliberately does **not** print raw secret values in its own normalized reports. If a secret detector reports a potential credential, rotate it through the relevant issuer and inspect access logs according to your incident procedure.

## Policies

Policies are human-reviewable YAML files under `rules/`. A policy explicitly selects controls, their required status, and their disposition. A tool that happens to be on `PATH` never affects a release unless the selected policy enables its control.

| Profile | Use it when | Main behavior |
|---|---|---|
| `rules/default-policy.yaml` | Local development and baseline assessment. | Runs the validated native controls. It is the recommended starting profile. |
| `rules/strict-ci-policy.yaml` | Protected-branch CI. | Runs the native pre-deployment controls with every configured control required and fail-closed error behavior. |
| `rules/external-adapters-policy.yaml` | A team has installed and calibrated the pinned Gitleaks and Semgrep binaries. | Replaces the bootstrap secret/SAST controls with required external adapters while retaining native FastAPI, configuration, CI, and dependency controls. |
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

The external profile is opt-in because third-party scanner output must be calibrated before it becomes a release authority. It activates isolated adapters for **Gitleaks 8.30.1** and **Semgrep 1.175.0**.

### Install and verify the scanners

Install Gitleaks from its official release channel and Semgrep through your approved software distribution process. Verify the executable path and version before using the profile. For Semgrep, an isolated uv tool installation can be used:

```bash
uv tool install "semgrep==1.175.0"
semgrep --version

gitleaks version
```

The policy declares the expected versions for traceability. Your team should pin the downloaded Gitleaks artifact or container digest through its own dependency-management process and ensure `gitleaks` and `semgrep` are available on `PATH` in the CI runner.

### Run the external profile

```bash
uv run before-deploy scan /path/to/repository \
  --policy rules/external-adapters-policy.yaml \
  --output-dir /tmp/before-deploy-external
```

The adapters use fixed argument lists, a minimal child-process environment, temporary reports outside the scanned repository, bounded report size, and timeouts. They do not execute project code, enable Semgrep autofix, allow Semgrep local builds, use remote Semgrep registry rules, or retain raw Gitleaks secrets in Before Deploy reports.

If either required binary is missing, times out, produces invalid JSON, or reports an internal scan error, the outcome is `ERROR` with exit code `20`. This is intentional fail-closed behavior.

> Treat external scanner rules and configuration as security-sensitive source code. Review changes through pull requests, pin tool versions, and test rule changes against the secure and vulnerable fixtures before enabling them on protected branches.

## Release-evidence verification

The `release-evidence-policy.yaml` profile is intentionally **not** a general development scan. It is for a release-candidate directory that contains the declared artifact and a downloaded GitHub attestation bundle. It also requires the explicitly versioned `uv`, `pip-audit`, and `gh` executables on `PATH`.

```bash
uv run before-deploy scan /path/to/release-candidate \\
  --policy rules/release-evidence-policy.yaml \\
  --output-dir /tmp/before-deploy-release-evidence
```

The profile audits a locked Python dependency set, requires a CycloneDX SBOM, and verifies the local artifact against the expected GitHub repository and signer-workflow identity. Missing tools, a missing lock/SBOM/artifact/bundle, an unverifiable attestation, or malformed evidence returns `ERROR` with exit code `20`; this is expected fail-closed behavior. The detailed contract and threat boundary are in [`docs/DEPENDENCY_PROVENANCE_MILESTONE.md`](docs/DEPENDENCY_PROVENANCE_MILESTONE.md).

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
| `SEC-SAST-001` | Enabled | Python AST patterns for selected raw SQL interpolation into execute calls. |
| `SEC-API-001` | Enabled | Declared FastAPI route decorators and visible `Depends`/`Security` declarations; not semantic proof of authorization. |
| `SEC-CONFIG-001` | Enabled | Explicit debug declarations in Python and selected configuration files; not effective cloud runtime state. |
| `SEC-CONFIG-002` | Enabled | Credentialed wildcard CORS patterns in common FastAPI/config forms. |
| `SEC-CICD-001` | Enabled when workflows are present | Selected GitHub Actions trigger, permission, and action-pin checks. |
| `SEC-DEP-001` | Enabled | Supported Python/Node manifest and lockfile presence; not vulnerability analysis yet. |
| `SEC-SECRET-GITLEAKS-001` | External profile | Gitleaks directory-scan findings, normalized without the raw secret. |
| `SEC-SAST-SEMGREP-001` | External profile | Checked-in local Semgrep rule findings, normalized without source excerpts. |
| `SEC-DEP-VULN-001` | Release-evidence profile | pip-audit JSON evidence against a declared Python lock/requirements input; it detects known advisories, not exploitability or non-Python packages. |
| `SEC-RELEASE-001` | Strict and release-evidence profiles | Presence and basic parseability of a CycloneDX JSON SBOM; not provenance validation. |
| `SEC-PROVENANCE-001` | Release-evidence profile | Offline `gh attestation verify` bundle verification with expected repository and signer workflow; it does not claim a generic SLSA level. |

Read the detailed control boundary and false-positive process in [`docs/CONTROL_CATALOG.md`](docs/CONTROL_CATALOG.md). The adapter trust boundary, failure semantics, and calibration requirements are in [`docs/EXTERNAL_ADAPTERS_MILESTONE.md`](docs/EXTERNAL_ADAPTERS_MILESTONE.md); the dependency and provenance evidence contract is in [`docs/DEPENDENCY_PROVENANCE_MILESTONE.md`](docs/DEPENDENCY_PROVENANCE_MILESTONE.md).

## Repository structure

```text
src/before_deploy/       # Deterministic kernel, native controls, and external adapters
tests/                   # Unit, integration, and fake-tool isolation tests
rules/                   # Versioned policy profiles and local Semgrep rules
docs/                    # Architecture, control catalog, and implementation contracts
fixtures/                # Intentionally secure and vulnerable FastAPI/Next.js repositories
.github/workflows/       # Hardened project CI
uv.lock                  # Reproducible development dependency lock
```

## Development and verification

Run the same checks used by repository CI:

```bash
uv sync --frozen --all-extras
uv run ruff check src tests
uv run pytest
uv run before-deploy scan . \
  --policy rules/default-policy.yaml \
  --output-dir reports/self-scan
```

The fake-tool tests exercise Gitleaks/Semgrep normalization, secret redaction, privacy flags, timeouts, missing binaries, scanner-reported errors, and the fail-closed path without requiring live scanner binaries or real credentials.

## Security principles

The project follows least privilege, isolated execution, explicit policy, fail-closed release behavior for required controls, immutable rule and tool versions, redacted evidence, bounded waivers, and developer-reviewed remediation. All repository content, scanner output, and future AI inputs are treated as untrusted data.

## Status and next steps

The deterministic kernel, isolated Gitleaks/Semgrep adapters, and dependency/provenance evidence foundation are implemented and tested. The next engineering milestone is to install and calibrate the pinned external tools in CI, generate and retain a release artifact plus signed attestation bundle, extend audit coverage beyond Python, and only then add tightly bounded AI assistance.

For the design rationale and phased roadmap, see [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) and [`docs/DEEP_ANALYSIS_AND_BUILD_BLUEPRINT.md`](docs/DEEP_ANALYSIS_AND_BUILD_BLUEPRINT.md).
