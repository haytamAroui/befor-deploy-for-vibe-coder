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
| 4. Scanner adapters | One bounded external adapter at a time. | Fixed arguments, isolated process, no secrets, controlled environment, report-size/time bounds, normalized redacted output, and policy opt-in. | Secure, vulnerable, malformed-report, missing-tool, timeout, and redaction tests pass. |
| 5. Fixture matrix | Secure, vulnerable, unsupported, and false-positive fixtures for every control. | Fixtures prove the stated detection contract—not comprehensive security. | Native and integration coverage exists before any policy profile makes the control a release gate. |
| 6. Coverage calibration | Domain status semantics and exclusions tied to selected capabilities. | Coverage remains diagnostic unless a future reviewed policy explicitly uses it. | No percentage score, compliance claim, or implicit clean status is emitted. |

## Current implementation position

The repository now has a narrow Python/FastAPI pack, a narrow Next.js/TypeScript pack, and the first Go reference pack. The Go pack contributes root-module checksum-presence evidence, direct Go TLS-verification disablement detection, one exact packaged offline dependency-vulnerability snapshot, and an optional Gosec adapter for selected injection, SSRF, and path-traversal evidence. The snapshot does not establish source reachability, indirect-dependency analysis, live-database freshness, general Go framework coverage, authorization, dataflow, runtime, or production-infrastructure coverage.

The Gosec adapter is a reference for future adapter work: it requires a policy-configured preinstalled executable, uses fixed arguments, disables module-network resolution, keeps modules read-only, ignores inline suppressions, and discards upstream source/details before generating a normalized finding. Gosec documents its own AST/SSA/taint-analysis coverage and JSON output modes; Before Deploy reports only the bounded upstream results it receives.[1]

## Prioritized next control families

The backlog is ordered by evidence quality and safety of implementation, not by trying to add every domain at once.

| Priority | Candidate domain/control family | Preconditions | Explicit non-goal for the first iteration |
|---|---|---|---|
| 1 | Next.js Server Actions and middleware boundary analysis. | Clear static AST-backed contract and secure/vulnerable/false-positive fixtures. | Claiming authorization correctness or runtime session assurance. |
| 2 | Python variable-to-`execute` dataflow expansion. | Precision benchmark and controlled Semgrep/native implementation. | Whole-program dataflow or dynamic SQL correctness claims. |
| 3 | FastAPI dynamic route review state. | Explicit diagnostic condition and policy treatment design. | Treating dynamic route construction as silently authenticated or clean. |
| 4 | Container and IaC adapters. | Isolated preinstalled scanners, deterministic inputs, normalized output, and artifact fixtures. | Cloud-account inspection, deployment changes, or runtime IAM guarantees. |
| 5 | Expand the Go snapshot through separately reviewed advisory boundaries. | Official-source verification, exact-version semantics, digest update, redaction review, and fixture matrix. | Live-database synchronization, arbitrary version ranges, reachability claims, or automatic remediation. |

## Advisory AI boundary

A future AI may explain a normalized redacted report and suggest remediation for human review. It may not modify the domain catalog, capability registry, policy, waivers, scanner configuration, findings, release outcome, branch state, deployment state, or secrets. It has no execution authority.

## References

[1]: https://github.com/securego/gosec "securego/gosec — documented Go AST, SSA, taint-analysis, JSON-output, and configuration behavior"
