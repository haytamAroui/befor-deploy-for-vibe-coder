# Implementation Plan — Milestone 1: Deterministic Security Gate

**Project:** Before Deploy for Vibe Coder  
**Status:** Approved for implementation  
**Milestone objective:** Deliver a local, reproducible Python CLI that discovers repository evidence, evaluates selected deterministic controls, applies explicit policy, and emits redacted JSON, Markdown, and SARIF-compatible reports.

> **Non-negotiable design rule:** The policy engine is deterministic and is the only component allowed to determine the gate outcome. AI assistance is deliberately excluded from this milestone because trustworthy, redacted findings must exist before an assistant can safely explain them.

## 1. Product increment

Milestone 1 creates the smallest complete vertical slice of Sentinel. A developer can run a command against a FastAPI or Next.js repository, receive findings that identify the rule, evidence, location, severity, and remediation, and obtain a final `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED` gate result. The same repository revision, rule pack, policy profile, and scan configuration must produce the same normalized result.

| Included in Milestone 1 | Deferred beyond Milestone 1 |
|---|---|
| Python package and command-line interface. | Hosted dashboard, multi-tenant storage, and user administration. |
| Repository inventory and deterministic scan manifest. | Cloud-runtime posture collection and Kubernetes admission control. |
| Findings schema, policy engine, waiver schema, and reports. | External waiver-approval service; waivers are loaded from reviewed local data initially. |
| Native configuration and CI workflow checks. | Comprehensive semantic authorization/data-flow analysis. |
| High-confidence lexical checks for injection and secrets. | Direct production integration with Gitleaks, Semgrep, pip-audit, npm audit, and Sigstore. |
| Unit, integration, golden-fixture, and policy tests. | AI explanation and patch-proposal agents. |
| A hardened project CI workflow. | Full SBOM/provenance generation and verification. |

## 2. Architectural boundaries

The codebase is divided into a stable domain core and replaceable adapters. The domain core must not know how a specific scanner produces data. Adapters return normalized `Finding` objects or a structured `ToolExecution` error. This permits native bootstrap checks now and mature external-tool adapters later without changing policy, reports, or CI consumers.

```text
CLI command
  └── ScanOrchestrator
        ├── RepositoryInventory
        ├── Control adapters (native or external)
        ├── FindingNormalizer
        ├── WaiverResolver
        ├── PolicyEngine
        └── ReportWriters (JSON, Markdown, SARIF)
```

| Module | Responsibility | Must not do |
|---|---|---|
| `models.py` | Defines immutable domain records and enums. | Read files, execute tools, or make policy decisions. |
| `inventory.py` | Resolves repository metadata and calculates reproducible content digests. | Interpret vulnerabilities or leak ignored-secret contents. |
| `controls/base.py` | Defines the control protocol and execution contract. | Contain control-specific policy logic. |
| `controls/*` | Produces findings for one named control family. | Change a release decision directly. |
| `policy.py` | Applies rules, tool health, and scoped waivers to normalized findings. | Scan a repository or mutate waiver data. |
| `waivers.py` | Validates waiver schema and matches fingerprints exactly. | Approve a waiver or broaden its scope. |
| `reports/*` | Serializes results in user and machine formats. | Recalculate policy or expose raw secret matches. |
| `orchestrator.py` | Coordinates inputs, controls, policy, and reporting. | Hide adapter errors or convert them to passes. |
| `cli.py` | Parses command-line arguments and maps outcomes to exit codes. | Implement scanning rules. |

## 3. Repository layout

```text
befor-deploy-for-vibe-coder/
├── pyproject.toml
├── README.md
├── src/
│   └── before_deploy/
│       ├── __init__.py
│       ├── cli.py
│       ├── models.py
│       ├── inventory.py
│       ├── orchestrator.py
│       ├── policy.py
│       ├── waivers.py
│       ├── controls/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── secrets.py
│       │   ├── injection.py
│       │   ├── fastapi_routes.py
│       │   ├── deployment_config.py
│       │   └── github_actions.py
│       └── reports/
│           ├── __init__.py
│           ├── json_report.py
│           ├── markdown_report.py
│           └── sarif_report.py
├── rules/
│   ├── default-policy.yaml
│   └── strict-policy.yaml
├── fixtures/
│   ├── vulnerable_fastapi_nextjs/
│   └── secure_fastapi_nextjs/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── golden/
├── docs/
│   ├── IMPLEMENTATION_PLAN.md
│   ├── CONTROL_CATALOG.md
│   └── DEEP_ANALYSIS_AND_BUILD_BLUEPRINT.md
└── .github/workflows/
    └── ci.yml
```

## 4. Domain model and contracts

The schema must be stable before scanner implementations grow. Every finding is tied to a rule, a rule version, an evidence location, an exact fingerprint, a confidence level, and a remediation. A control that cannot execute is not a benign result.

| Record | Required fields | Purpose |
|---|---|---|
| `ScanManifest` | scan ID, repository path, repo digest, Git revision if available, start/end timestamps, policy digest, ruleset version. | Binds the report to reproducible scan inputs. |
| `ToolExecution` | control ID, status, version, start/end time, error code/message, evidence scope. | Distinguishes a completed scan from a failed or skipped scan. |
| `Finding` | rule ID/version, title, location, fingerprint, severity, confidence, disposition, message, remediation, evidence fields. | Common contract for native and external scanner output. |
| `Waiver` | waiver ID, finding fingerprint, rule ID, source digest, approver, justification, compensating controls, expiry. | Constrains accepted risk to one exact result and scope. |
| `PolicyDecision` | outcome, reason codes, blocking findings, waiver-required findings, advisory findings, errors. | Provides the only release gate decision. |
| `ScanResult` | manifest, executions, findings, waivers, decision. | Parent object used by all report writers. |

### 4.1 Gate-state semantics

| Outcome | Deterministic condition | CLI exit code |
|---|---|---:|
| `PASS` | Every required control completed, no unwaived blocking or waiver-required finding remains. | `0` |
| `BLOCK` | One or more unwaived findings match a rule whose disposition is `BLOCK`. | `10` |
| `WAIVER_REQUIRED` | One or more unwaived findings match a rule requiring explicit approval. | `11` |
| `ERROR` | A required control fails, an input/waiver/policy is invalid, or report generation fails. | `20` |
| `NOT_EVALUATED` | No controls apply or a profile explicitly limits scope. | `0`, accompanied by a visible warning |

No count threshold may change the outcome. An individual control’s configured disposition, required evidence, execution state, and exact waiver match determine the decision.

## 5. Initial control catalog

Milestone 1 uses native, intentionally narrow detectors. Each rule is a bootstrap rule; the native implementation is later replaceable by an external adapter. The initial versions prioritize transparent behavior and testability over broad detection claims.

| Control ID | Evidence and predicate | Default disposition | Native implementation in this milestone | Future adapter |
|---|---|---|---|---|
| `SEC-SECRET-001` | No likely committed private key or high-confidence API token pattern. | `BLOCK` | Scan text files within configured limits; redact matched value and fingerprint the finding. | Gitleaks or equivalent. |
| `SEC-SAST-001` | No Python raw SQL f-string or `.format()` construction passed to `execute`. | `BLOCK` | AST inspection of Python files. | Semgrep curated pack. |
| `SEC-API-001` | Mutating FastAPI routes declare an authorization dependency or appear in an explicit reviewed public-route allowlist. | `BLOCK` | AST scan of decorator and dependency forms; load allowlist from policy. | Framework-aware semantic analyzer. |
| `SEC-CONFIG-001` | Production-oriented configuration does not enable `DEBUG=True`. | `BLOCK` | Inspect `.env*`, YAML, JSON, TOML, and Python settings values using contextual parsers. | Deployment-manifest and runtime evidence adapter. |
| `SEC-CONFIG-002` | CORS does not combine wildcard origins and credentials. | `BLOCK` | AST/config inspection of common FastAPI and settings forms. | Runtime configuration adapter. |
| `SEC-CICD-001` | Workflows avoid untrusted checkout with privileged triggers, default write-all permissions, or third-party actions not pinned to full SHA. | `BLOCK` | Parse GitHub workflow YAML text conservatively and detect known unsafe forms. | OpenSSF Scorecard and GitHub policy adapter. |
| `SEC-DEP-001` | Supported Python/Node projects have a lockfile when a manifest is present. | `BLOCK` | Inspect `pyproject.toml`, `requirements*.txt`, `package.json`, and known lockfiles. | Package-manager-specific integrity adapter. |
| `SEC-RELEASE-001` | A release profile contains a CycloneDX SBOM reference. | `WAIVER_REQUIRED` | Verify named SBOM path is present and parseable as JSON. | CycloneDX generator/validator. |

A rule must not silently report that it checked information it did not inspect. For example, an absent `.github/workflows` directory makes the CI control `NOT_APPLICABLE`; a malformed required workflow makes it `ERROR`; a wildcard CORS declaration makes it `BLOCK` only when credentials are demonstrably enabled.

## 6. Policy profile format

Policy profiles must be human-reviewable and committed with the code. YAML is used for readability. The CLI calculates a SHA-256 digest of the exact profile file and records it in every manifest.

```yaml
schema_version: 1
profile: default
public_fastapi_routes:
  - path: /healthz
    methods: [GET]
controls:
  SEC-SECRET-001:
    required: true
    disposition: BLOCK
  SEC-SAST-001:
    required: true
    disposition: BLOCK
  SEC-API-001:
    required: true
    disposition: BLOCK
  SEC-CONFIG-001:
    required: true
    disposition: BLOCK
  SEC-CONFIG-002:
    required: true
    disposition: BLOCK
  SEC-CICD-001:
    required: false
    disposition: BLOCK
  SEC-DEP-001:
    required: true
    disposition: BLOCK
  SEC-RELEASE-001:
    required: false
    disposition: WAIVER_REQUIRED
```

A strict profile promotes relevant deployment and release evidence checks to required status. A profile cannot reduce a native scanner `ERROR` into `PASS`; a separate `allow_nonrequired_control_errors` option may only make errors nonblocking for controls that are explicitly nonrequired.

## 7. Waiver model

Milestone 1 loads waivers from a local YAML file supplied to the CLI. The workflow and repository review process provide the approval boundary until a dedicated approval service exists. A waiver is valid only if all exact match conditions hold.

| Field | Validation requirement |
|---|---|
| `id` | Stable unique identifier. |
| `finding_fingerprint` | Exact fingerprint equality; no wildcard support. |
| `rule_id` | Exact rule match. |
| `repository_digest` | Exact scan repository digest equality. |
| `expires_at` | ISO 8601 UTC timestamp strictly in the future. |
| `approved_by` | Non-empty accountable identity. |
| `justification` | Non-empty, reviewable explanation. |
| `compensating_controls` | Non-empty description of risk mitigation. |

The initial design intentionally makes waivers short-lived and brittle. A changed source revision produces a changed repository digest and invalidates the waiver; the developer must re-request acceptance after a material change.

## 8. CLI user experience

```bash
before-deploy scan ./my-service \
  --policy rules/default-policy.yaml \
  --waivers .sentinel/waivers.yaml \
  --output-dir reports
```

The CLI prints a compact terminal summary, writes `report.json`, `report.md`, and `report.sarif`, and exits using the documented decision code. It supports `--format terminal|json|markdown|sarif`, `--max-file-bytes`, policy selection, output-directory selection, and an optional waiver file. The first milestone does not scan Git history by default, but the manifest clearly records that scope limitation.

## 9. Reporting requirements

Every report includes the policy digest, rule versions, repository digest, scanner status, and limitations. Secret findings must never include the raw suspected credential. The SARIF writer emits a valid 2.1.0-compatible subset containing tool metadata, rule metadata, results, locations, fingerprints, and redacted messages.

| Format | Primary audience | Required content |
|---|---|---|
| Terminal | Developer and CI log reader. | Final outcome, errors, summary by severity/disposition, top findings, report paths. |
| JSON | Automation and future control plane. | Complete normalized scan result with redacted evidence. |
| Markdown | Pull request and release reviewer. | Decision rationale, findings grouped by action, waivers, limitations, and remediation. |
| SARIF | Code scanning integrations. | Rule descriptors and code locations where available; no raw secrets. |

## 10. Test plan

Tests are part of the control design, not a later QA activity. Each rule requires a vulnerable fixture, a secure fixture, and a rule-specific false-positive guard. The policy engine requires an exhaustive decision-state matrix.

| Test group | Mandatory cases |
|---|---|
| Domain unit tests | Enum serialization, stable fingerprints, manifest digest behavior, timestamp behavior, and redaction. |
| Control unit tests | Positive, negative, malformed, ignored-path, and size-limit cases for each control. |
| Policy unit tests | `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, `NOT_EVALUATED`, expired waiver, mismatched fingerprint, and missing required execution. |
| Report tests | JSON schema-like assertions, no secret leakage, stable Markdown sections, SARIF minimum required fields. |
| Integration tests | Scan secure and vulnerable FastAPI/Next.js fixtures; verify expected exit code and golden report fields. |
| CI self-scan | The project scans itself under its default profile and treats control errors as failures. |

## 11. Hardened project CI

The repository CI workflow must model the product’s own recommendations. It uses read-only default permissions, non-privileged `pull_request` events, pinned full-SHA third-party actions where an action is necessary, Python version pinning, dependency installation from the project definition, unit/integration test execution, a self-scan, and report-artifact upload without secrets.

The build workflow does not use `pull_request_target`, does not check out untrusted code in privileged context, and does not grant write permissions to a test job. A later release workflow will use a separately reviewed environment and artifact-attestation permissions.

## 12. Milestone acceptance criteria

Milestone 1 is complete when the following are demonstrated in CI and locally:

1. A vulnerable fixture with a mock token, raw SQL f-string, unauthenticated mutating FastAPI route, debug setting, unsafe CORS, missing lockfile, and unsafe GitHub workflow returns `BLOCK` with the expected controls and no secret value in outputs.
2. A secure fixture returns `PASS` under the default profile.
3. A control execution error on a required control returns `ERROR`, never `PASS`.
4. A matching, unexpired waiver changes only the matching finding’s behavior; an expired or mismatched waiver has no effect.
5. The JSON, Markdown, and SARIF reports contain the manifest and decision data and remain redacted.
6. The package passes formatting/linting, type-oriented checks where configured, and all tests.
7. The repository’s CI executes the test suite and a self-scan with least-privilege workflow permissions.

## 13. Implementation order

| Ordered work package | Files primarily affected | Completion signal |
|---|---|---|
| **WP-1: Domain and configuration** | `pyproject.toml`, `models.py`, policy/waiver loaders, default policy. | Schemas serialize and validate; policy digest is stable. |
| **WP-2: Inventory and orchestration** | `inventory.py`, `orchestrator.py`, control protocol. | A no-op scan produces a manifest and `NOT_EVALUATED`. |
| **WP-3: Native controls** | `controls/*.py`, fixture repositories. | Every initial rule has positive/negative tests. |
| **WP-4: Decision and reporting** | `policy.py`, `reports/*`, CLI. | Known fixture returns correct decision, reports, and exit code. |
| **WP-5: CI and hardening** | `.github/workflows/ci.yml`, self-scan settings. | CI is read-only and validates the project. |
| **WP-6: Review and documentation** | Catalog, README, changelog notes. | Limitations and next adapter work are accurately documented. |

## 14. Deferred roadmap after this milestone

The immediate next increment replaces bootstrap detectors with adapters to Gitleaks, Semgrep, pip-audit, npm audit, CycloneDX, and provenance verification. It also adds baseline management, secret-history scanning under explicit consent, stronger FastAPI dependency/data-flow recognition, and a protected waiver workflow. Only after reports are redacted and controls are stable should the project add the read-only AI explanation and patch-proposal services described in the architecture blueprint.
