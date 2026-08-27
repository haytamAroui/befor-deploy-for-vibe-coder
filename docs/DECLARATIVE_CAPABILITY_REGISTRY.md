# Declarative Capability Registry

**Status:** Implemented deterministic registry

The capability registry is the reviewed metadata layer between technology evidence and the existing controls/adapters. It makes selection traceable without creating executable plugins, autonomous planning, or a second release authority.

> **Authority boundary:** A registry manifest cannot contain a command, executable path, shell fragment, URL, secret, environment override, policy rule, waiver, deployment instruction, or arbitrary scanner argument. It only maps a fixed registered implementation ID to versioned applicability metadata and exclusions. The separate packaged Security Domain + Control Catalog maps reviewed capabilities to security domains. The policy engine remains the sole component that produces a release outcome.

## 1. Trusted source and loading model

The built-in registry is shipped as package data under `src/before_deploy/capabilities/manifests/`. The package owns `catalog.yaml`, which explicitly lists every allowed manifest. The loader does not discover capability manifests from the target repository, from the current directory, or from the network.

| Item | Current rule |
|---|---|
| Catalog schema | `1` |
| Catalog version | `0.7.0` |
| Catalog digest | SHA-256 over canonical schema-approved semantic fields, not raw YAML formatting or source paths. |
| Manifest source | Packaged, version-controlled YAML listed by `catalog.yaml`. |
| Duplicate YAML mapping keys | Rejected. |
| Unknown fields | Rejected. |
| Unknown implementation IDs | Rejected. |
| Duplicate capability IDs or implementation IDs | Rejected. |
| Policy-to-registry check | Every configured policy control is covered by a test-backed registered implementation. |

The registry contains only capabilities for controls and bounded adapters already implemented in this repository. It deliberately does not pre-register PHP, Rust, Kubernetes, CodeQL, OSV, or any other capability without a real reviewed implementation and regression fixtures. The registered Trivy capability covers only its implemented staged Dockerfile/Containerfile and Terraform `.tf` configuration boundary; it is not a generic infrastructure-scanner registration.

## 2. Capability manifest contract

Each manifest has this strict shape. The fields are data, not instructions.

| Field | Meaning |
|---|---|
| `schema_version` | Must be integer `1`. |
| `id` | Stable capability identifier, such as `control.native.nextjs-public-env`. |
| `version` | Capability metadata version. |
| `implementation_id` | Exactly one existing approved control/adapter ID, such as `SEC-NEXT-ENV-001`. |
| `kind` | `CONTROL` or `ADAPTER`. It describes the already-implemented execution path; it cannot construct one. |
| `title` | Redaction-safe capability label. |
| `applies_when` | Optional fixed `languages`, `frameworks`, `requires_github_workflow`, and/or `required_project_signals` predicates evaluated against the deterministic project profile. |
| `exclusions` | Explicit coverage limits preserved in plan/report output. |

Only the four `applies_when` keys listed above are accepted. A future manifest field requires a schema version, loader validation, documentation, fixtures, and tests before it can be accepted.

## 3. Selection and provenance

The execution path is deterministic and one-way:

1. The selected policy constructs its configured controls/adapters using existing code.
2. The packaged registry verifies that each implementation has exactly one approved manifest.
3. The deterministic profile evaluates the manifest’s fixed applicability predicates.
4. Compatible controls run; incompatible configured controls receive visible `NOT_APPLICABLE` executions.
5. The planner records a `CapabilitySelection` for each runnable implementation.
6. The policy engine evaluates executions, findings, and waivers as before.

Every `SecurityAnalysisPlan` includes policy name/digest, capability-catalog version/digest, security-domain-catalog version/digest, and evidence. Every selection includes its capability ID/version, implementation ID, kind, rationale, policy name/digest, capability-catalog digest, and evidence IDs. The separate domain catalog attaches stable `DOMAIN-` identifiers to coverage expectations. This explains a selection without allowing the plan to choose unconfigured tools or modify policy.

## 4. Coverage semantics

The coverage auditor reads the capability registry, the separate domain/control catalog, and observed execution statuses. It is diagnostic only.

| Status | Exact meaning |
|---|---|
| `COVERED` | All selected registered capabilities mapped to the domain completed. This means only that the approved scoped checks ran; it is not a claim of exhaustive security assurance. |
| `PARTIAL` | One or more selected mapped capabilities did not complete, without an execution error. |
| `ERROR` | A selected mapped capability returned an execution error. This is distinct from findings and remains visible even if a non-required policy allows the final gate to pass. |
| `UNAVAILABLE` | No approved registry capability covers the observed domain. |
| `NOT_SELECTED` | A compatible approved registry capability exists, but the active policy did not select its implementation. |
| `NOT_APPLICABLE` | All registry capabilities mapped to the observed domain are incompatible with the deterministic profile. |
| `DECLARED_REVIEW_REQUIRED` | Bounded documentation declared a domain; implementation evidence requires review. The declaration is not a finding and cannot affect the release decision. |

## 5. Current capability boundary

The current catalog describes native secrets, Python SAST/configuration, FastAPI static routes plus dynamic-route review metadata, Next.js public-environment/cookie/CORS plus one Server Action local-guard-marker control, GitHub Actions, dependency-manifest, offline Go snapshot, and SBOM controls. It also describes the existing Gitleaks, Semgrep, pip-audit, Gosec, offline provenance, and staged Trivy Dockerfile/Containerfile/Terraform configuration adapters. Adapter manifests never carry their executable, version pin, timeouts, paths, or arguments; these remain explicit policy and adapter-code concerns.

## 6. Adding a future capability

A future capability must be introduced only with a real reviewed control or bounded adapter. Add a manifest through `catalog.yaml`, validate the package-data build, test malformed manifests and duplicate references, provide secure/vulnerable fixtures when a detector is added, update domain mappings/exclusions, and document the detection scope. Adding YAML metadata alone must never imply a scanner exists or security coverage is available.

For the taxonomy, control contracts, and informative standards-reference boundary, see [`SECURITY_DOMAIN_CONTROL_CATALOG.md`](SECURITY_DOMAIN_CONTROL_CATALOG.md). Future declarative skill packs remain deferred. If introduced, they must be metadata-only and resolve only to already registered capabilities. They may not include executable code or expand policy authority.
