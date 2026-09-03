# Domain Assurance

## Purpose

Domain assurance adds two read-only/control-plane concepts on top of the existing architecture without creating a second release authority:

1. a **Domain × Technology × ControlContract matrix** derived from the existing capability and security-domain catalogs; and
2. optional **policy-owned minimum coverage requirements** evaluated by the existing deterministic policy engine.

The policy engine remains the only component that can produce a release outcome.

## Assurance matrix

The matrix answers:

> For a security domain and technology, which reviewed control contracts currently exist?

It is derived from:

- capability metadata for language/framework applicability; and
- control-contract metadata for domain mapping, detection scope, and exclusions.

Technology axes are deterministic:

- framework-scoped capability → `framework:<name>`;
- otherwise language-scoped capability → `language:<name>`;
- otherwise → `GLOBAL`.

A framework-specific capability is not duplicated into its language column.

Generate the current matrix with:

```bash
uv run python scripts/render_assurance_matrix.py
```

The default output is `reports/domain-assurance-matrix.md`.

Contract counts are diagnostic. They do not establish security, compliance, absence of vulnerabilities, or release approval.

## Assurance policy

Coverage remains diagnostic by default. Existing policies therefore preserve their current behavior.

A policy may opt into minimum coverage for stable domain identifiers:

```yaml
assurance:
  minimum_domain_coverage:
    DOMAIN-SECRETS-001: COVERED
    DOMAIN-INJECTION-001: PARTIAL
```

Only `PARTIAL` and `COVERED` are valid minimums:

- `PARTIAL` accepts actual `PARTIAL` or `COVERED`;
- `COVERED` accepts only actual `COVERED`;
- `UNAVAILABLE`, `NOT_SELECTED`, `NOT_APPLICABLE`, `DECLARED_REVIEW_REQUIRED`, and `ERROR` satisfy neither minimum.

The flow remains:

```text
CapabilityRegistry + SecurityDomainCatalog
              |
              v
       AssuranceMatrix
       (diagnostic only)
              |
              v
        CoverageAudit
              |
              v
 explicit AssurancePolicy
              |
              v
       policy.evaluate()
              |
              v
       PolicyDecision
```

An unmet assurance requirement produces `GateOutcome.ERROR`, because the active release policy lacks required evidence depth. It is not emitted as a synthetic vulnerability finding.

Stable reason-code families are:

```text
ASSURANCE_COVERAGE_AUDIT_MISSING
ASSURANCE_DOMAIN_MISSING:<domain-id>
ASSURANCE_COVERAGE_INSUFFICIENT:<domain-id>:<actual>:REQUIRES_<minimum>
ASSURANCE_COVERAGE_SATISFIED:<domain-id>:<actual>
```

Assurance errors are namespaced in `PolicyDecision.error_control_ids` as `ASSURANCE:<domain-id>`.

## Non-goals

This layer does not:

- calculate security percentages or scores;
- infer that a domain is secure;
- promote documentation requirements into implementation facts;
- allow `CoverageAudit` to block independently;
- create waivers automatically;
- let AI change assurance requirements;
- turn a single bounded control into proof of complete domain security.
