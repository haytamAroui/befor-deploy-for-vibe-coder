# 21 Security Domains Roadmap

**Status:** Product roadmap and catalog-evolution contract. This document does not add a control, scanner, policy disposition, compliance result, or release authority.

## Product model

Before Deploy uses **security domains**, not a claim of twenty-one universal security checks. A domain is a security surface with bounded activation evidence, explicit exclusions, and a visible coverage state. A domain may map to multiple control contracts; each contract maps to one reviewed capability and one existing implementation. The technology-specific capability determines whether a control can run, while the versioned policy remains the sole authority for `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED`.

```text
Repository and requirements evidence
                ↓
       Adaptive project profile
                ↓
       Security analysis plan
                ↓
Security-domain/control catalog + capability registry
                ↓
  Selected controls and approved adapters
                ↓
Normalized findings + diagnostic coverage audit
                ↓
      Versioned deterministic policy engine
                ↓
             Release outcome
```

> A requirement declaration can activate a diagnostic domain, but it never proves that the feature exists, that a control is implemented, or that an application is secure.

## The 21 foundational domains

The catalog defines these foundational surfaces: authentication, authorization, endpoint security, input validation, injection, CORS, secrets, sensitive data, error handling, file uploads, database security, data integrity, API assurance, observability, security testing, production configuration, supply chain, CI/CD security, session security, API security, and payment integration. It also keeps separate extensions where conflation would hide scope: JSON Web Tokens, passwords, rate limiting/resource consumption, database reliability, container security, infrastructure-as-code security, SSRF, transport security, and path traversal.

A domain does not become covered by its presence in this list. It appears as `UNAVAILABLE`, `NOT_SELECTED`, `NOT_APPLICABLE`, `PARTIAL`, `COVERED`, `DECLARED_REVIEW_REQUIRED`, or `ERROR` according to the versioned catalog, observed evidence, selected capabilities, and actual execution state.

## Delivery sequence

| Stage | Deliverable | Authority boundary | Completion condition |
|---|---|---|---|
| 1. Taxonomy | Versioned security-domain/control catalog with current mappings and explicit unmapped domains. | Informational only. | Complete: catalog v0.2.0 defines 21 foundational domains, 9 extensions, and maps only real controls. |
| 2. Control decomposition | Small contracts such as authorization-object access, command injection, path traversal, or JWT algorithm validation. | A contract cannot run code or create a policy result. | Every contract has a stable ID, explicit scope/exclusions, an approved capability, and fixture-backed tests before it is mapped. |
| 3. Technology mappings | Per-control language/framework applicability and evidence requirements. | Registry metadata cannot discover tools or select unconfigured scanners. | Each mapping points only to an existing implementation and has precise non-applicability behavior. |
| 4. Scanner adapters | One bounded external adapter at a time. | Fixed arguments, isolated process, no secrets, controlled environment, report-size/time bounds, normalized redacted output, and policy opt-in. | First container/IaC adapter complete: Trivy config staging, version verification, malformed-report, missing-tool, timeout, path-containment, suppression-neutralization, and redaction tests pass locally. |
| 5. Fixture matrix | Secure, vulnerable, unsupported, and false-positive fixtures for every control. | Fixtures prove the stated detection contract—not comprehensive security. | Native and integration coverage exists before any policy profile makes the control a release gate. |
| 6. Coverage calibration | Domain status semantics and exclusions tied to selected capabilities. | Coverage remains diagnostic and cannot alter a policy decision. | No percentage score, compliance claim, or implicit clean status is emitted. |

## Current implementation position

The repository now has a narrow Python/FastAPI pack, a narrow Next.js/TypeScript pack, and the first Go reference pack. The Python pack includes direct SQL interpolation and one local straight-line variable-to-execute flow. Its FastAPI route control emits structural review metadata for dynamic paths or `api_route` method values rather than treating them as findings or policy inputs. The Next.js pack includes public-environment, session-cookie, static-CORS, and separate narrow module-level and named-inline Server Action direct-mutation/local-guard-marker checks. Its proxy/middleware presence is structural metadata only, not authorization evidence. The Go pack contributes root-module checksum-presence evidence, direct Go TLS-verification disablement detection, two exact packaged offline direct-dependency vulnerability boundaries, and an optional Gosec adapter for selected injection, SSRF, and path-traversal evidence. These packs do not establish framework-wide authorization, dataflow, runtime, source reachability, indirect-dependency analysis, live-database freshness, or production-infrastructure coverage.

The Gosec adapter is a reference for future adapter work: it requires a policy-configured preinstalled executable, uses fixed arguments, disables module-network resolution, keeps modules read-only, ignores inline suppressions, and discards upstream source/details before generating a normalized finding. Gosec documents its own AST/SSA/taint-analysis coverage and JSON output modes; Before Deploy reports only the bounded upstream results it receives.[1]

The first container/IaC adapter is now `SEC-TRIVY-CONFIG-001`. It is deliberately a small external boundary: a dedicated opt-in policy requires a preinstalled Trivy `0.74.0` binary, verifies that version, stages only inventory-included Dockerfile/Containerfile variants and Terraform `.tf` files, neutralizes inline Trivy ignores, omits target ignore/config/module inputs, and invokes Trivy with fixed misconfiguration-only offline arguments. It maps only normalized rule ID, severity, artifact category, staged-relative path, and positive line to the deterministic policy engine. A static secure/vulnerable/ambiguous/suppression/unsupported corpus now prepares a future human-reviewed air-gap calibration and has structural staging tests, but no Trivy binary was downloaded or run and no protected-branch policy adoption is claimed. Container images, Compose, Helm, Kubernetes, CloudFormation, Terraform plans/tfvars/modules/state, cloud accounts, runtime behavior, target code, downloads, and target-supplied scanner configuration remain outside this control.[2] [3]

## Prioritized next control families

The backlog is ordered by evidence quality and safety of implementation, not by trying to add every domain at once.

| Priority | Candidate domain/control family | Preconditions | Explicit non-goal for the first iteration |
|---|---|---|---|
| 1 | Perform a human-reviewed real-binary Trivy air-gap calibration against the prepared static corpus before any protected-branch adoption. | The version-pinned binary must be provisioned independently; runner egress isolation, distribution provenance, normalized/redacted reports, observed rule IDs, and false-positive/negative review must be retained. | Downloading or installing Trivy in this repository or CI workflow; container image scanning, cloud-account inspection, deployment changes, runtime IAM guarantees, or a claim of comprehensive IaC coverage. |
| 2 | Completed incremental Go snapshot expansion: add reviewed `GO-2020-0001` Gin boundary alongside the existing x/text boundary. | Official Go-database review, exact direct-root version semantics, refreshed digest, redaction tests, and affected/fixed/indirect fixtures are implemented. | Live-database synchronization, arbitrary version ranges, reachability claims, or automatic remediation remain excluded. |
| 3 | Completed Next.js Server Action precision increment: named nested async functions with inline `use server`. | Separate `SEC-NEXT-INLINE-ACTION-001` implementation, policy, contract, secure/vulnerable/page-only/excluded fixtures, and no authority change. | Arrow actions, module-level/exported actions, directives after executable code, proxy/middleware, helper guards, and semantic authorization remain excluded. |
| 4 | Expand Python local SQL-flow coverage through separate contracts. | Precision benchmarks for aliases, branches, awaits, wrappers, and imports. | Whole-program dataflow, ORM safety, or treating an absent finding as secure SQL. |
| 5 | Evolve FastAPI dynamic-route review only after calibration. | Fixture corpus for variables, aliases, router prefixes, registration APIs, and report-volume bounds. | Reclassifying review metadata as a finding or using it as an implicit policy gate. |

## Advisory AI boundary

A future AI may explain a normalized redacted report and suggest remediation for human review. It may not modify the domain catalog, capability registry, policy, waivers, scanner configuration, findings, release outcome, branch state, deployment state, or secrets. It has no execution authority.

## References

[1]: https://github.com/securego/gosec "securego/gosec — documented Go AST, SSA, taint-analysis, JSON-output, and configuration behavior"
[2]: https://trivy.dev/docs/latest/references/configuration/cli/trivy_config/ "Trivy — config command reference"
[3]: https://trivy.dev/docs/latest/advanced/air-gap/ "Trivy — connectivity considerations and embedded checks"
