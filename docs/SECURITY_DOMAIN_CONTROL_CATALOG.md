# Security Domain + Control Catalog

**Version:** 0.8.0
**Authority:** Informational only; it is not a policy profile, a scanner, a compliance assessment, or a release authority.

## Purpose and authority boundary

This packaged catalog translates a broad security taxonomy into two deliberately separate metadata layers. A **security domain** identifies a security surface that may be visible through bounded repository evidence. A **control contract** records the exact scope and exclusions of a real, reviewed capability already registered in `before_deploy.capabilities`. Neither layer executes a command, discovers a tool, changes policy, creates a waiver, or changes the `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, or `NOT_EVALUATED` decision.

> **Only the versioned deterministic policy engine is a release authority.** A domain appearing in a report is not proof that the domain is secured; a green capability result is not proof of exhaustive analysis, production readiness, or regulatory compliance.

The catalog provides visibility rather than artificial certainty. A detected or declared security surface can therefore be `COVERED`, `PARTIAL`, `UNAVAILABLE`, `NOT_SELECTED`, `NOT_APPLICABLE`, `DECLARED_REVIEW_REQUIRED`, or `ERROR`. In particular, a requirement signal is a bounded documentation fact, not implementation evidence.

## Trusted loading model

The catalog is loaded only from reviewed YAML files packaged inside `before_deploy.domains.manifests`. Before it is used, the loader rejects duplicate YAML keys, unknown fields, unknown references, malformed local manifest paths, unsupported categories, duplicate domain/control/capability/implementation IDs, unknown domain references, unknown capability references, implementation mismatches, URLs or command markers in normal text fields, and references outside the fixed official allowlist.

| Metadata layer | Stable identifier prefix | Permitted purpose | Not permitted |
|---|---|---|---|
| Security domain | `DOMAIN-` | Define a security surface, activation predicates, exclusions, and informative standards references | Commands, URLs outside root references, scanner configuration, findings, dispositions, compliance claims |
| Control contract | `CONTROL-` | Map one real approved capability and implementation to one or more domains with exact scope/exclusions | Executable code, arbitrary arguments, tool discovery, policy overrides, waivers, remediation |
| Capability registry | Existing `control.*` / `adapter.*` | Map reviewed implementation IDs to fixed applicability predicates | Domain taxonomy authority, arbitrary execution, policy authority |
| Policy profile | Existing `rules/*.yaml` | Decide explicit dispositions for normalized findings and required-control errors | Automatic compliance certification or AI override |

The catalog digest is a canonical SHA-256 digest over semantic metadata. The scan plan and coverage audit record its version and digest, so a report can be tied to the exact domain/control definitions used to produce it.

## Selected control-contract provenance

`SecurityAnalysisPlan` version `0.4.0` records a `control_contract_selections` collection alongside capability selections. Every capability or adapter implementation actually selected by the versioned policy must resolve to exactly one reviewed control contract in this catalog. Each recorded item contains only the contract ID and version, capability ID, implementation ID, mapped domain IDs, bounded detection scope, and declared exclusions.

This is a traceability feature, not a second planner, scanner, coverage engine, or policy input. The catalog cannot cause an implementation to run; the policy still selects the runnable implementation, and the deterministic policy engine alone determines the release outcome. If a selected implementation has no unique contract or its contract points to another capability, plan construction fails closed rather than inventing coverage.

The provenance model provides a stable path for future multi-language work. A future Go, PHP, Rust, Java, or other-language capability may receive a contract only after its real reviewed implementation, registry entry, bounded applicability, tests, exclusions, and explicit policy-selection boundary exist. No placeholder contract, scanner configuration, command, or coverage claim is accepted before that point.

## Security-domain taxonomy

The first catalog contains the **twenty-one foundational categories** adapted from the reviewed checklist as a taxonomy only. It also contains nine separately named extensions where collapsing a distinct surface would obscure coverage limits. A domain marked **mapped** has at least one reviewed current control contract; an **unmapped** domain has no approved implementation and remains explicit in coverage output only when its bounded applicability condition is observed.

| ID | Domain | Current mapping posture | Present limitation |
|---|---|---|---|
| `DOMAIN-AUTHENTICATION-001` | Authentication | Unmapped | Requirement evidence does not prove an authentication mechanism, MFA posture, or identity assurance level. |
| `DOMAIN-AUTHORIZATION-001` | Authorization | Mapped for one narrow Next.js Server Action guard-marker pattern | A local guard marker does not prove authentication, authorization, ownership, tenant isolation, proxy coverage, or policy correctness. |
| `DOMAIN-ENDPOINT-SECURITY-001` | Endpoint security | Unmapped | Endpoint inventory, runtime headers, request limits, and enforcement are not inferred. |
| `DOMAIN-INPUT-VALIDATION-001` | Input validation | Unmapped | Schema validation and runtime normalization are not inferred. |
| `DOMAIN-INJECTION-001` | Injection protection | Mapped | Native Python SQL interpolation, optional local Semgrep, and opt-in Gosec are narrow; most injection families remain out of scope. |
| `DOMAIN-JWT-SECURITY-001` | JSON Web Token security | Unmapped | JWT presence, algorithms, token lifecycle, and key handling are not inferred. |
| `DOMAIN-PASSWORD-SECURITY-001` | Password security | Unmapped | Password support and context-specific verifier policy are not inferred. |
| `DOMAIN-RATE-LIMITING-001` | Rate limiting and resource consumption | Unmapped | Limits, business-flow controls, and enforcement location are not inferred. |
| `DOMAIN-CORS-001` | Cross-origin resource sharing | Mapped | Only supported static Python and Next.js patterns are checked. |
| `DOMAIN-SECRETS-001` | Secrets and sensitive configuration | Mapped | Native patterns and optional Gitleaks do not establish secret-store or rotation posture. |
| `DOMAIN-SENSITIVE-DATA-001` | Sensitive data handling | Unmapped | Response filtering, encryption, retention, and privacy compliance are not inferred. |
| `DOMAIN-ERROR-HANDLING-001` | Error handling | Unmapped | Runtime handlers, stack traces, and production error responses are not inferred. |
| `DOMAIN-FILE-UPLOAD-001` | File upload security | Unmapped | Content validation, malware scanning, isolation, archives, and image handling are not inferred. |
| `DOMAIN-DATABASE-SECURITY-001` | Database security | Unmapped | Transport, IAM, encryption, backups, and network posture are not inferred. |
| `DOMAIN-DATABASE-RELIABILITY-001` | Database reliability and performance | Unmapped | Query plans, pools, caching, and runtime performance are separate assurance topics. |
| `DOMAIN-DATA-INTEGRITY-001` | Data integrity | Unmapped | Constraints, transactions, concurrency, and tenant isolation are not inferred. |
| `DOMAIN-API-ASSURANCE-001` | API validation and assurance | Unmapped | An OpenAPI file does not prove request/response validation or inventory completeness. |
| `DOMAIN-OBSERVABILITY-001` | Security observability | Unmapped | Logging content, retention, alerts, and production monitoring are not inferred. |
| `DOMAIN-SECURITY-TESTING-001` | Security testing evidence | Unmapped | Test quantity and code-coverage percentages do not prove application security. |
| `DOMAIN-PRODUCTION-CONFIGURATION-001` | Production configuration | Mapped | Static Python debug configuration does not determine effective deployed configuration. |
| `DOMAIN-SUPPLY-CHAIN-001` | Software supply chain | Mapped | Existing controls provide limited Python/Node and Go module evidence, one bounded Go dependency-vulnerability snapshot, plus limited SBOM/provenance evidence; they do not establish a SLSA level. |

| Extension ID | Distinct extension | Current mapping posture | Present limitation |
|---|---|---|---|
| `DOMAIN-API-SECURITY-001` | API security | Mapped for FastAPI route authentication declarations | Does not prove API inventory, authorization correctness, SSRF safety, or runtime configuration. |
| `DOMAIN-SESSION-SECURITY-001` | Session security | Mapped for narrow Next.js cookie options | Does not infer custom cookie wrappers, expiry, token generation, or session lifecycle. |
| `DOMAIN-CICD-SECURITY-001` | CI/CD security | Mapped for selected GitHub Actions hardening checks | Does not inspect repository settings, runners, identities, or external CI platforms. |
| `DOMAIN-CONTAINER-SECURITY-001` | Container security | Mapped for the opt-in staged Trivy Dockerfile/Containerfile configuration adapter | Images, Compose, registries, image execution, runtime posture, and deployed configuration are not inspected. |
| `DOMAIN-IAC-SECURITY-001` | Infrastructure-as-code security | Mapped for the opt-in staged Trivy Terraform `.tf` configuration adapter | Plans, tfvars, modules, providers, state, computed values, cloud state, IAM, and deployment posture are not inspected. |
| `DOMAIN-SSRF-001` | Server-side request forgery | Mapped for opt-in Gosec on root Go modules | Declared external URL fetching is not proof of an SSRF implementation or mitigation; Gosec coverage is limited to upstream findings. |
| `DOMAIN-PAYMENT-INTEGRATION-001` | Payment integration security | Unmapped | Payment declarations do not prove provider, webhook, or business-flow security. |
| `DOMAIN-TRANSPORT-SECURITY-001` | Transport security | Mapped for direct Go TLS configuration | Only direct `tls.Config` literals disabling verification are checked; custom verification and runtime transport configuration are not inferred. |
| `DOMAIN-PATH-TRAVERSAL-001` | Path traversal protection | Mapped for opt-in Gosec on root Go modules | Gosec coverage is limited to upstream findings; custom sanitization and runtime file-system behavior are not inferred. |

## Current control contracts

The catalog maps **only the twenty-one reviewed capability implementations already registered**. It adds no scanner and cannot make an unconfigured adapter run.

| Control contract | Capability / implementation | Domain mapping | Selection boundary |
|---|---|---|---|
| `CONTROL-SECRETS-NATIVE-001` | `control.native.secrets` / `SEC-SECRET-001` | Secrets | Repository-wide bounded source patterns. |
| `CONTROL-SECRETS-GITLEAKS-001` | `adapter.gitleaks-directory` / `SEC-SECRET-GITLEAKS-001` | Secrets | Explicit external policy configuration only. |
| `CONTROL-INJECTION-PYTHON-001` | `control.native.python-sast` / `SEC-SAST-001` | Injection | Python AST direct SQL interpolation plus one local straight-line simple-name assignment into a standalone execute/executemany call; no branch, alias, import, object-state, or interprocedural analysis. |
| `CONTROL-INJECTION-SEMGREP-001` | `adapter.semgrep-python-local` / `SEC-SAST-SEMGREP-001` | Injection | Explicit external policy configuration only. |
| `CONTROL-API-FASTAPI-001` | `control.native.fastapi-api` / `SEC-API-001` | API security | Supported static FastAPI mutating routes plus structural `REVIEW_REQUIRED` metadata for dynamic paths or `api_route` methods; the metadata is neither a finding nor a gate input. |
| `CONTROL-CONFIG-PYTHON-DEBUG-001` | `control.native.python-debug-config` / `SEC-CONFIG-001` | Production configuration | Supported static Python/configuration sources. |
| `CONTROL-CORS-PYTHON-001` | `control.native.python-cors` / `SEC-CONFIG-002` | CORS | Supported static Python/configuration sources. |
| `CONTROL-CICD-GITHUB-ACTIONS-001` | `control.native.github-actions` / `SEC-CICD-001` | CI/CD security | Visible GitHub Actions workflows only. |
| `CONTROL-SUPPLY-DEPENDENCY-MANIFEST-001` | `control.native.dependency-manifest` / `SEC-DEP-001` | Software supply chain | Supported Python/Node manifests and lockfiles only. |
| `CONTROL-SUPPLY-PIP-AUDIT-001` | `adapter.pip-audit-python` / `SEC-DEP-VULN-001` | Software supply chain | Explicit release-evidence policy only. |
| `CONTROL-SUPPLY-SBOM-001` | `control.native.release-sbom` / `SEC-RELEASE-001` | Software supply chain | SBOM presence/basic parseability only. |
| `CONTROL-SUPPLY-PROVENANCE-001` | `adapter.github-attestation-offline` / `SEC-PROVENANCE-001` | Software supply chain | Explicit local artifact/bundle verification only. |
| `CONTROL-SUPPLY-GO-MODULE-001` | `control.native.go-module-integrity` / `SEC-GO-MODULE-001` | Software supply chain | Root `go.mod` dependency declarations and root `go.sum` presence only. |
| `CONTROL-SUPPLY-GO-VULNERABILITY-SNAPSHOT-001` | `control.native.go-vulnerability-snapshot` / `SEC-GO-VULN-001` | Software supply chain | Explicit Go snapshot policy; exact direct root dependency version against two packaged reviewed advisory boundaries only. |
| `CONTROL-TRANSPORT-GO-TLS-001` | `control.native.go-tls-verification` / `SEC-GO-TLS-001` | Transport security | Direct literal `tls.Config{InsecureSkipVerify: true}` only. |
| `CONTROL-GOSEC-STATIC-ANALYSIS-001` | `adapter.gosec-go-module` / `SEC-GOSEC-001` | Injection, SSRF, path traversal | Explicit external-adapters policy, preinstalled Gosec, fixed local/offline arguments, and normalized redacted report only. |
| `CONTROL-CONTAINER-IAC-TRIVY-CONFIG-001` | `adapter.trivy-config-isolated` / `SEC-TRIVY-CONFIG-001` | Container security, infrastructure-as-code security | Explicit `trivy-config-policy.yaml` only; preinstalled version-verified Trivy 0.74.0, fixed offline misconfiguration-only arguments, isolated staged Dockerfile/Containerfile variants and Terraform `.tf`, and normalized redacted report only. |
| `CONTROL-NEXTJS-PUBLIC-ENV-001` | `control.native.nextjs-public-env` / `SEC-NEXT-ENV-001` | Secrets | Direct sensitive-looking public variable names only. |
| `CONTROL-AUTHORIZATION-NEXT-SERVER-ACTION-001` | `control.native.nextjs-server-action-local-guard` / `SEC-NEXT-ACTION-001` | Authorization | Module-level Server Action direct `db`/`prisma` mutation before a local guard marker; proxy/middleware is structural metadata only. |
| `CONTROL-NEXTJS-SESSION-COOKIE-001` | `control.native.nextjs-session-cookie` / `SEC-NEXT-COOKIE-001` | Session security | Explicit unsafe static cookie-option combinations only. |
| `CONTROL-NEXTJS-CORS-001` | `control.native.nextjs-static-cors` / `SEC-NEXT-CORS-001` | CORS | Static `next.config.*` header arrays only. |

## Standards-reference boundary

References in this catalog provide **context only**. They do not grant compliance, determine severity, establish a policy disposition, or supply universal numeric thresholds. NIST describes SSDF as high-level secure-development practices that can be integrated into an SDLC; at the time this catalog was written, the SSDF 1.2 announcement identified the revision as an initial public draft.[1] OWASP’s API Top 10 identifies security risk categories including authorization failures, resource consumption, SSRF, misconfiguration, inventory, and unsafe API consumption; it is not a scanner conformance test.[2] OWASP’s CI/CD guidance similarly provides risk and hardening guidance rather than a certification.[3] SLSA v1.2 is approved and uses distinct tracks with separate requirements, so the existing provenance capability explicitly does not claim any generic SLSA level.[4]

| Reference ID | Informative use in this catalog | Does not mean |
|---|---|---|
| `REF-NIST-SSDF-DRAFT-1-2` | Secure-development taxonomy context | Conformance, certification, or a full SSDF assessment |
| `REF-OWASP-API-2023` | API-domain and control-design context | Complete API testing or OWASP compliance |
| `REF-OWASP-CICD` | CI/CD, secrets, and supply-chain hardening context | Complete SCM, runner, identity, or pipeline assurance |
| `REF-SLSA-1-2-TRACKS` | Scope boundary for SBOM/provenance evidence | SLSA Build or Source track attainment |

## Adding a domain or control

Add a domain only when it has a stable security-surface definition and bounded deterministic activation evidence. An unmapped domain is valid and should report as `UNAVAILABLE` when activated. Add a control contract only after a concrete native control or bounded external adapter exists, has a reviewed capability-registry entry, has fixture-backed tests, declares exclusions, and is selected only by an explicit policy profile.

Do not add placeholders, universal numeric thresholds, runtime claims, arbitrary tool definitions, automatic remediation, or compliance language. New external adapters remain subject to the existing isolated execution contract and must be introduced independently from the domain metadata.

## References

[1]: https://www.nist.gov/news-events/news/2025/12/secure-software-development-framework-ssdf-version-12-available-public "NIST: SSDF Version 1.2 Initial Public Draft Announcement"
[2]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ "OWASP API Security Top 10 — 2023"
[3]: https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html "OWASP CI/CD Security Cheat Sheet"
[4]: https://slsa.dev/spec/v1.2/tracks "SLSA v1.2 Tracks"
