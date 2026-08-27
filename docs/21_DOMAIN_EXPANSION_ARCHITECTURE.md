# 21-Security-Domain Expansion Architecture

## Overview

This document describes the architecture for expanding Before Deploy into a **technology-adaptive, evidence-driven security platform covering 21 security domains**. The goal is NOT to build 21 Python validators, but to create a scalable framework where each domain can contain multiple controls and technology-specific implementations.

## Core Principle

> **The scanner discovers evidence.**  
> **The planner determines applicable approved capabilities.**  
> **Controls detect.**  
> **Coverage reports limitations.**  
> **Policy decides.**

Only the policy engine produces release decisions (PASS/BLOCK/WAIVER_REQUIRED/ERROR). Coverage and domain activation are informational.

---

## Architecture Model

```
SECURITY DOMAIN (what security surface exists)
      ↓
CONTROL CONTRACT (what exact security property is tested)
      ↓
CAPABILITY (which reviewed implementation can test it)
      ↓
IMPLEMENTATION (actual detector/scanner)
```

### Example: Injection Domain

```
DOMAIN-INJECTION-001
        │
        ├── CONTROL-INJ-SQL-PYTHON-001
        │       │
        │       └── capability.python.sql-injection
        │               │
        │               └── SEC-SAST-001 (native Python AST analysis)
        │
        ├── CONTROL-INJ-SQL-SEMGREP-001
        │       │
        │       └── adapter.semgrep-python-local
        │               │
        │               └── SEC-SAST-SEMGREP-001
        │
        └── CONTROL-INJ-COMMAND-GO-001 (future)
                │
                └── capability.go.command-injection
                        │
                        └── future Go implementation
```

---

## The 21 Security Domains

| #  | Domain ID                            | Category                  | Activation Evidence                          |
|----|--------------------------------------|---------------------------|----------------------------------------------|
| 1  | DOMAIN-AUTHENTICATION-001            | APPLICATION_SECURITY      | REQUIREMENT-AUTHENTICATION                     |
| 2  | DOMAIN-AUTHORIZATION-001             | APPLICATION_SECURITY      | REQUIREMENT-AUTHORIZATION                      |
| 3  | DOMAIN-ENDPOINT-SECURITY-001         | APPLICATION_SECURITY      | REQUIREMENT-API                                |
| 4  | DOMAIN-INPUT-VALIDATION-001          | APPLICATION_SECURITY      | REQUIREMENT-API                                |
| 5  | DOMAIN-INJECTION-001                 | APPLICATION_SECURITY      | languages: Python                              |
| 6  | DOMAIN-JWT-SECURITY-001              | APPLICATION_SECURITY      | REQUIREMENT-AUTHENTICATION                     |
| 7  | DOMAIN-PASSWORD-SECURITY-001         | APPLICATION_SECURITY      | REQUIREMENT-AUTHENTICATION                     |
| 8  | DOMAIN-RATE-LIMITING-001             | APPLICATION_SECURITY      | REQUIREMENT-API                                |
| 9  | DOMAIN-CORS-001                      | CONFIGURATION_SECURITY    | languages: Python, frameworks: Next.js         |
| 10 | DOMAIN-SECRETS-001                   | CONFIGURATION_SECURITY    | repository_wide: true                          |
| 11 | DOMAIN-SENSITIVE-DATA-001            | APPLICATION_SECURITY      | REQUIREMENT-PERSONAL-DATA                      |
| 12 | DOMAIN-ERROR-HANDLING-001            | APPLICATION_SECURITY      | REQUIREMENT-API                                |
| 13 | DOMAIN-FILE-UPLOAD-001               | APPLICATION_SECURITY      | REQUIREMENT-FILE-UPLOAD                        |
| 14 | DOMAIN-DATABASE-SECURITY-001         | APPLICATION_SECURITY      | REQUIREMENT-DATABASE                           |
| 15 | DOMAIN-DATABASE-RELIABILITY-001      | ASSURANCE                 | REQUIREMENT-DATABASE                           |
| 16 | DOMAIN-DATA-INTEGRITY-001            | APPLICATION_SECURITY      | REQUIREMENT-DATABASE                           |
| 17 | DOMAIN-API-ASSURANCE-001             | ASSURANCE                 | REPOSITORY-API-OPENAPI, REQUIREMENT-API        |
| 18 | DOMAIN-OBSERVABILITY-001             | ASSURANCE                 | REQUIREMENT-OBSERVABILITY                      |
| 19 | DOMAIN-SECURITY-TESTING-001          | ASSURANCE                 | REQUIREMENT-SECURITY-TESTING                   |
| 20 | DOMAIN-PRODUCTION-CONFIGURATION-001  | CONFIGURATION_SECURITY    | languages: Python, frameworks: Next.js         |
| 21 | DOMAIN-SUPPLY-CHAIN-001              | SUPPLY_CHAIN_SECURITY     | languages: JavaScript, Python, TypeScript      |

### Extension Domains (Optional)

These provide more precise surfaces where foundational categories are too broad:

- DOMAIN-CICD-SECURITY-001
- DOMAIN-CONTAINER-SECURITY-001
- DOMAIN-IAC-SECURITY-001
- DOMAIN-SSRF-001
- DOMAIN-PAYMENT-INTEGRATION-001
- DOMAIN-SESSION-SECURITY-001
- DOMAIN-API-SECURITY-001

---

## Domain Activation Logic

A domain becomes active ONLY through bounded evidence:

### Evidence Types

```python
- file extension (.py, .ts, .go, .rs, etc.)
- manifest (package.json, pyproject.toml, go.mod)
- lockfile (uv.lock, poetry.lock, yarn.lock)
- framework marker (next.config.js, main.go)
- infrastructure file (Dockerfile, *.tf)
- OpenAPI artifact (openapi.yaml)
- CI workflow (.github/workflows/*.yml)
- requirement document (requirements.md signals)
```

### Activation Statuses

```python
class ActivationStatus(str, Enum):
    ACTIVATED = "ACTIVATED"                    # Domain applies + capabilities available
    NOT_APPLICABLE = "NOT_APPLICABLE"          # Domain doesn't match profile/evidence
    DECLARED_REVIEW_REQUIRED = "DECLARED_REVIEW_REQUIRED"  # Requirement declared, needs human review
    UNAVAILABLE = "UNAVAILABLE"                # Domain applies but no capabilities for this profile
```

### Example Activation

```json
{
  "domain_id": "DOMAIN-FILE-UPLOAD-001",
  "activation_status": "DECLARED_REVIEW_REQUIRED",
  "evidence_ids": ["REQUIREMENT-FILE-UPLOAD"],
  "rationale": "File-upload capability explicitly declared in requirements.md",
  "applicable_controls": [],
  "available_capability_ids": [],
  "unavailable_capability_ids": []
}
```

**Critical**: Domain activation NEVER produces a release decision. It only informs coverage.

---

## Control Contract Schema

Control contracts define detection scope WITHOUT executable code:

```yaml
schema_version: 1

id: CONTROL-INJ-SQL-PYTHON-001
version: 1.0.0

title: SQL Injection Protection (Python)

domains:
  - DOMAIN-INJECTION-001

capabilities:
  - capability.python.sql-injection

implementation_ids:
  - SEC-SAST-001

applicability:
  languages:
    - Python

required_evidence:
  - language.python

detection_scope:
  - direct SQL interpolation in supported Python AST patterns

exclusions:
  - runtime-only database configuration
  - unsupported dynamic execution paths

references:
  - REF-OWASP-ASVS
```

### What Control Contracts CANNOT Contain

```text
❌ commands
❌ URLs for scanners
❌ shell code
❌ credentials
❌ scanner arguments
❌ policy dispositions
❌ waivers
❌ deployment instructions
```

This trust boundary is enforced by the schema loader.

---

## Capability Registry

Capabilities map control contracts to actual implementations:

```yaml
# control.python-sast.yaml
schema_version: 1

capability_id: capability.python.sql-injection
version: 1.0.0

implementation_id: SEC-SAST-001
kind: CONTROL

title: Native Python SQL injection detection

languages:
  - Python

frameworks: []

requires_github_workflow: false

security_domains:
  - DOMAIN-INJECTION-001

exclusions:
  - Interprocedural dataflow
  - ORM-based queries
  - Non-Python code
```

### Capability Levels (Maturity Classification)

```text
LEVEL 0 — DETECTION        Technology detected
LEVEL 1 — METADATA         Domain/control mapping exists
LEVEL 2 — STATIC EVIDENCE  Deterministic local control exists
LEVEL 3 — SEMANTIC ANALYSIS AST/data-flow/static scanner exists
LEVEL 4 — EXTERNAL ANALYSIS Approved external scanner exists
LEVEL 5 — RUNTIME/INFRA    External environment evidence exists
```

---

## Implementation Roadmap

### Phase 1: Foundation ✅ (COMPLETED)

Already implemented in current repository:

- ✅ Repository evidence collection
- ✅ Adaptive project profiling
- ✅ Requirements signal detection
- ✅ Security analysis planning
- ✅ Capability registry
- ✅ 21 security domains defined
- ✅ Control catalog
- ✅ Coverage auditor
- ✅ Policy authority boundary
- ✅ Domain evaluator (`src/before_deploy/domains/evaluator.py`)

### Phase 2: Control Decomposition (NEXT)

**PR-1: `decompose-injection-authorization-supply-chain-controls`**

Implement control-level granularity for three domains:

1. **Injection Domain**
   - CONTROL-INJ-SQL-PYTHON-001 (existing SEC-SAST-001)
   - CONTROL-INJ-COMMAND-001 (new)
   - CONTROL-INJ-XSS-001 (new)

2. **Authorization Domain**
   - CONTROL-AUTHZ-BOLA-001 (new)
   - CONTROL-AUTHZ-BFLA-001 (new)

3. **Supply Chain Domain**
   - CONTROL-SUPPLY-DEP-VULN-001 (existing pip-audit)
   - CONTROL-SUPPLY-SBOM-001 (existing)
   - CONTROL-SUPPLY-PROVENANCE-001 (existing)

**Deliverables:**
- Control contract YAML files
- Control-level coverage tracking
- Migration mapping (old IDs → new IDs)
- Test fixtures (secure/vulnerable/unsupported/false-positive)
- Zero new scanners

### Phase 3: Complete Domain Taxonomy

Decompose all remaining domains into control families:

```text
Authentication: AUTHN-CREDENTIALS, AUTHN-MFA, AUTHN-SESSION-INIT, ...
Authorization: AUTHZ-BOLA, AUTHZ-BFLA, AUTHZ-PROPERTY, ...
Input Validation: INPUT-SCHEMA, INPUT-TYPE, INPUT-LENGTH, ...
...
```

Many controls will remain `UNAVAILABLE` initially—this is intentional and honest.

### Phase 4: Multi-Language Proof (Go Example)

Prove architecture is not Python-centric:

```text
Go service
  ↓
Go profile detection
  ↓
Go capability registry entries
  ↓
Injection controls (SQL, Command)
  ↓
CodeQL/Semgrep adapter
  ↓
Normalized findings
  ↓
Coverage audit
  ↓
Policy evaluation
```

### Phase 5: Adapter Substitution (PHP Example)

Prove adapter substitution model works for languages NOT supported by CodeQL:

```text
PHP + Laravel
  ↓
Semgrep PHP rules (not CodeQL)
  ↓
Composer dependency analysis
  ↓
Same domain/control model
```

### Phase 6-10: Advanced Capabilities

- Rust/Java/C# semantic analysis
- Container/IaC security
- Runtime evidence integration
- AI advisory layer (read-only)

---

## Technology Capability Matrix

| Language | Detection | Dependencies | SAST           | Framework Support    | Deep Controls |
|----------|-----------|--------------|----------------|----------------------|---------------|
| Python   | ✅         | ✅            | ✅ (native+Semgrep) | FastAPI, Django      | Phase 1       |
| JS/TS    | ✅         | ✅            | ✅ (Semgrep)       | Next.js, Express     | Phase 1       |
| Go       | ✅         | ✅            | Planned (CodeQL)   | Gin, Echo            | Phase 4       |
| Rust     | ✅         | ✅            | Planned            | Axum, Actix          | Phase 6       |
| Java     | ✅         | ✅            | Planned (CodeQL)   | Spring Boot          | Phase 6       |
| Kotlin   | ✅         | ✅            | Planned (CodeQL)   | Spring Boot          | Phase 6       |
| C#       | ✅         | ✅            | Planned (CodeQL)   | ASP.NET Core         | Phase 6       |
| PHP      | ✅         | ✅            | Semgrep only       | Laravel, Symfony     | Phase 5       |
| Ruby     | ✅         | ✅            | Planned            | Rails                | Phase 6       |
| C/C++    | ✅         | ⚠️ Limited    | Planned (CodeQL)   | —                    | Later         |
| Swift    | ✅         | ✅            | Planned (CodeQL)   | —                    | Later         |

**Key**: ✅ = Implemented, ⚠️ = Partial, Planned = In roadmap

---

## Scanner Adapter Architecture

External scanners must implement strict security boundaries:

```python
class ScannerAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    def supports(self, profile: ProjectProfile) -> bool:
        """Check if adapter can analyze this project profile."""
        ...

    def execute(self, request: AdapterRequest) -> AdapterResult:
        """Execute scanner with bounded timeout, output, and environment."""
        ...
```

### Security Requirements

```text
✅ fixed implementation (no arbitrary commands)
✅ bounded timeout
✅ bounded output size
✅ minimal environment
✅ no inherited secrets
✅ no arbitrary shell execution
✅ no project-code execution
✅ structured output parsing
✅ redaction of sensitive data
✅ explicit failure states
✅ version provenance tracking
```

### Planned Adapters

```text
src/before_deploy/adapters/
├── base.py (protocol)
├── codeql.py (compiled languages: Go, Java, C#, Rust, Swift)
├── semgrep.py (broad language support)
├── gitleaks.py (secrets)
├── dependency.py (ecosystem-specific)
├── sbom.py (CycloneDX validation)
├── provenance.py (Sigstore verification)
├── container.py (Trivy integration)
└── iac.py (Terraform/Kubernetes)
```

**Critical**: CodeQL compiled-language analysis may involve builds. Before Deploy will NEVER allow arbitrary repository build commands. Only predefined, approved CI workflow modes are permitted.

---

## Finding Normalization

All scanners feed the same normalized finding model:

```python
@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str
    rule_id: str
    control_id: str
    domain_id: str
    capability_id: str
    implementation_id: str
    
    severity: Severity
    confidence: Confidence
    
    message: str
    location: Location | None
    evidence: Mapping[str, str]
    
    technology: str | None
    language: str | None
    framework: str | None
    
    repository_digest: str
    policy_digest: str
    catalog_digest: str
    
    tool_version: str
```

### Severity vs Confidence

**Critical distinction:**

```text
severity = impact if true
confidence = likelihood that the detector is correct
```

Example:
```text
HIGH severity + LOW confidence → Human review (not automatic block)
```

A scanner saying "Potential SQL injection" ≠ "Confirmed exploitable SQL injection."

---

## Coverage Model

Coverage reporting shows what was actually assessed:

```text
Authentication
    NOT_APPLICABLE

Authorization
    UNAVAILABLE

Injection
    PARTIAL
      SQL (Python)         COVERED
      Command (Python)     UNAVAILABLE
      XSS                  UNAVAILABLE

Secrets
    COVERED

Supply Chain
    PARTIAL
      Dependency Scan      COVERED
      SBOM Presence        COVERED
      Provenance           COVERED
      Artifact Integrity   UNAVAILABLE

File Upload
    DECLARED_REVIEW_REQUIRED
```

### Coverage Statuses

```python
class CoverageStatus(str, Enum):
    COVERED = "COVERED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_SELECTED = "NOT_SELECTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DECLARED_REVIEW_REQUIRED = "DECLARED_REVIEW_REQUIRED"
    ERROR = "ERROR"
```

**Important**: Coverage CANNOT modify policy decisions unless explicitly configured in policy.

---

## Policy Interaction

Policy remains the SOLE release authority:

```python
GateOutcome ∈ {PASS, BLOCK, WAIVER_REQUIRED, ERROR, NOT_EVALUATED}
```

Coverage may inform policy but never overrides it:

```yaml
# Example policy configuration (optional)
coverage_requirements:
  - domain: DOMAIN-SUPPLY-CHAIN
    minimum_status: COVERED
    
  - domain: DOMAIN-SECRETS-001
    minimum_status: PARTIAL
```

But this is opt-in. Default behavior: coverage is informational only.

---

## Testing Strategy

Every control needs four fixture types:

```text
fixtures/
  go/
    injection/
      secure/           # Clean code, should PASS
      vulnerable/       # Real vulnerability, should FAIL
      unsupported/      # Pattern not covered, should be UNAVAILABLE
      false_positive/   # Looks vulnerable but isn't, should PASS
      
  php/
    upload/
      secure/
      vulnerable/
      unsupported/
      false_positive/
```

### Scanner Calibration Tests

Every adapter must pass:

```text
✅ precision test (low false positive rate)
✅ recall test (detects known vulnerabilities)
✅ timeout test (bounded execution)
✅ malformed output test (graceful failure)
✅ redaction test (no secret leakage)
✅ unsupported-language test (proper skip)
✅ missing-tool test (graceful degradation)
✅ large-repository test (performance)
```

---

## What "21-Domain Coverage" Means

**DO NOT SAY:**
> "Before Deploy checks 21 security vulnerabilities."

**CORRECT STATEMENT:**
> **Before Deploy evaluates 21 security domains and expands each applicable domain into versioned security controls based on the technologies and evidence present in the project.**

And:
> **Coverage is explicit: implemented, partial, unavailable, not selected, not applicable, or review required.**

---

## Definition of Done

### For Each Domain

```text
✅ domain definition (in domains.yaml)
✅ activation conditions (profile/evidence predicates)
✅ control families defined
✅ applicability model (languages/frameworks)
✅ unavailable semantics documented
✅ coverage semantics defined
✅ standards references (OWASP, NIST, SLSA)
✅ exclusions clearly stated
```

### For Each Control

```text
✅ control contract (controls.yaml)
✅ registered capability (capabilities/)
✅ actual implementation (controls/ or adapters/)
✅ deterministic provenance
✅ secure fixture
✅ vulnerable fixture
✅ unsupported fixture
✅ false-positive fixture
✅ normalized finding output
✅ documentation
```

### For Each Scanner Adapter

```text
✅ version pin
✅ trust boundary (no arbitrary execution)
✅ timeout enforcement
✅ output limit
✅ redaction logic
✅ failure handling
✅ calibration tests
✅ CI integration test
```

---

## Key Design Decisions

### 1. No Global Security Score

**Decision**: Never implement `Security Score = 87%`

**Rationale**: Until formally calibrated methodology exists, report:
```text
- domains assessed
- controls assessed  
- controls unavailable
- controls not selected
- execution errors
- declared-review domains
```

### 2. Separation of Concerns

```text
Controls      → Detection only, no policy decisions
Policy        → Disposition assignment, no source analysis
Domains       → Metadata only, no execution
Capabilities  → Registry metadata, no construction
Coverage      → Informational, cannot change outcomes
```

### 3. Fail-Closed Design

```text
Unknown controls → ERROR
Unregistered implementations → ERROR
Missing policy config → ERROR
Control exceptions → Captured as ERROR status
```

### 4. Determinism

```text
✅ Sorted file traversal
✅ Frozen dataclasses
✅ No random/non-deterministic operations
✅ Reproducible repository digests
```

### 5. Redaction Safety

```text
✅ Findings never include raw secrets
✅ Evidence uses digests/hashes
✅ Fingerprints from normalized payloads
```

---

## Next Steps

### Immediate (Phase 2)

1. **Create control contract YAML files** for Injection, Authorization, Supply Chain
2. **Implement control-level coverage** in coverage auditor
3. **Add migration mapping** (SEC-SAST-001 → CONTROL-INJ-SQL-PYTHON-001)
4. **Build test fixtures** for each control family
5. **Update documentation** with control decomposition examples

### Short Term (Phase 3)

1. Decompose remaining 18 domains into control families
2. Mark unavailable controls explicitly
3. Expand capability registry with multi-language entries

### Medium Term (Phase 4-5)

1. Implement Go ecosystem proof-of-concept
2. Implement PHP/Laravel adapter substitution
3. Add CodeQL and Semgrep adapters

### Long Term (Phase 6-10)

1. Rust/Java/C# support
2. Container/IaC security
3. Runtime evidence integration
4. AI advisory layer (read-only)

---

## References

- OWASP API Security Top 10 (2023)
- NIST SSDF 1.1 (current), SP 800-218 Rev. 1 (draft)
- SLSA v1.2 (separate Build and Source tracks)
- GitHub Language Support Documentation
- CodeQL Supported Languages

---

## Conclusion

This architecture transforms Before Deploy from a simple scanner into a **comprehensive security posture management platform**. The key insight is that 21 domains ≠ 21 validators. Instead:

```text
21 domains × N control families × M implementations = Scalable security coverage
```

The foundation is already in place. Phase 2 (control decomposition) establishes the stable contract model from which multi-language support, external adapters, and advanced capabilities can grow without changing the kernel.
