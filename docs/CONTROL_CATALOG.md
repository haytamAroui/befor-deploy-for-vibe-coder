# Control Catalog — Milestone 1

This catalog describes the deterministic native controls shipped in the first build milestone. The controls intentionally target high-confidence patterns in bounded repository evidence. They do **not** prove that a deployed application is secure, complete, compliant, or free of business-logic vulnerabilities.

| Control | Default profile action | Evidence inspected | Milestone-1 detection boundary | Next adapter direction |
|---|---|---|---|---|
| `SEC-SECRET-001` | Block | Bounded text files in the working tree. | Private-key markers, selected provider token shapes, and high-confidence secret assignments. The suspected value is never written to reports. | Gitleaks with explicitly approved history scope. |
| `SEC-SAST-001` | Block | Parseable Python source. | SQL f-string, `%` formatting, and `.format()` passed directly to `execute` or `executemany`. | Curated Semgrep and framework-specific AST rules. |
| `SEC-API-001` | Block | Parseable FastAPI routes and declared dependencies. | Mutating routes without a visible `Depends`/`Security` dependency or exact public-route allowlist entry. Dependency presence is not proof of correct authorization. | Dependency/data-flow and policy-aware route analysis. |
| `SEC-CONFIG-001` | Block | Python and selected configuration files. | Explicit `DEBUG=True` or `DEBUG=true` declarations. It does not establish the deployed effective configuration. | Deployment and runtime evidence adapters. |
| `SEC-CONFIG-002` | Block | FastAPI middleware calls and selected configuration files. | Wildcard origins combined with credentialed CORS. | Framework and runtime configuration adapters. |
| `SEC-NEXT-ENV-001` | Block when Next.js is detected | Direct `process.env.NEXT_PUBLIC_*` references in bounded JS/TS source. | Names that clearly indicate a secret, private credential, password, token, or session are rejected. It does not evaluate values, computed lookups, server-only variables, or data flow. | TypeScript AST/data-flow rules and client-boundary analysis. |
| `SEC-NEXT-COOKIE-001` | Block when Next.js is detected | Direct static `cookies().set(...)` or cookie-store setter calls in bounded JS/TS source. | Explicit insecure `httpOnly`, `secure`, or `sameSite` options on a statically named session/auth/token cookie. It does not infer omitted options or inspect wrappers. | TypeScript AST analysis, cookie-wrapper models, and route context. |
| `SEC-NEXT-CORS-001` | Block when Next.js is detected | Static `headers: [...]` blocks in `next.config.*`. | Credentialed wildcard CORS header pairs with literal values. It does not inspect middleware, proxies, environment interpolation, or runtime header generation. | Runtime/proxy evidence and framework-aware configuration analysis. |
| `SEC-CICD-001` | Block when run | GitHub workflow YAML. | `write-all`, privileged workflow triggers that also check out repository content, and third-party actions without full-SHA pins. | GitHub policy API and OpenSSF Scorecard. |
| `SEC-DEP-001` | Block | Root dependency manifests and lockfiles. | Missing recognized Python or Node lockfile. It does not inspect CVEs or package integrity yet. | pip-audit, npm audit, OSV, lockfile integrity verification. |
| `SEC-RELEASE-001` | Strict-release profile only | CycloneDX JSON candidate files. | Missing or non-CycloneDX JSON SBOM. | CycloneDX generation, SBOM integrity, and provenance verification. |

## Detector health

An adapter failure is recorded as `ERROR`. When a policy marks that control as required, the release outcome is `ERROR` rather than a pass. A control that cannot apply because its technology is absent is `NOT_APPLICABLE`; it is visibly recorded and is not counted as a pass.

## False-positive process

A finding may be fixed, accepted temporarily by a narrowly scoped waiver, or used to improve a reviewed rule. A waiver requires the exact finding fingerprint, rule, repository digest, accountable approver, justification, compensating controls, and future expiry. It cannot suppress a control-execution error.
