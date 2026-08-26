# Before Deploy for Vibe Coder

**Before Deploy for Vibe Coder** is a deterministic pre-deployment security-control tool with bounded, read-only AI assistance. It is designed to help FastAPI and Next.js teams prevent defined security failures before release without treating an LLM as the authority that decides whether a deployment is safe.

> The deterministic policy engine is the only release authority. AI may explain a finding or suggest a patch, but it may not approve a release, change policy, access secrets, execute arbitrary commands, or merge code.

## Initial product scope

The first release targets Python/FastAPI and TypeScript/Next.js repositories delivered through GitHub Actions. It will inventory repository evidence, run established security tools, normalize findings, apply an explicit release policy, and produce redacted SARIF and JSON evidence bundles.

| Component | Initial responsibility |
|---|---|
| Deterministic scan kernel | Builds a scan manifest, invokes restricted adapters, and records tool health. |
| Security adapters | Integrate secret detection, SAST, dependency scanning, CI workflow checks, SBOM creation, and release-provenance verification. |
| Policy engine | Produces `PASS`, `BLOCK`, `WAIVER_REQUIRED`, or `ERROR` using a versioned ruleset. |
| Evidence layer | Emits redacted SARIF, normalized JSON, a human summary, and integrity metadata. |
| AI assistance | Explains redacted findings and proposes developer-reviewed patches only. |

## Non-goals

This project is not a compliance-certification service, a penetration-test replacement, a proof that production is secure, or an autonomous deployment system. It will not claim to provide SOC 2, ISO 27001, NIST SSDF, GDPR, EU CRA, NIS2, or AI Act compliance.

## Planned first hard gates

The first implementation will focus on high-confidence controls: committed secrets, selected injection patterns, missing authentication on mutating FastAPI routes, production debug settings, unsafe credentialed CORS, lockfile and dependency security, unsafe CI workflow configuration, release SBOM presence, and verified provenance.

A failed required scanner will generate `ERROR`; it must not be interpreted as a passing security check.

## Repository structure

```text
src/                 # Deterministic Sentinel kernel and tool adapters
tests/               # Rule, integration, and golden-repository tests
rules/               # Versioned rule packs and policy profiles
docs/                # Architecture and product documentation
fixtures/            # Intentionally safe and vulnerable test repositories
.github/workflows/   # Hardened continuous-integration workflows
```

## Build sequence

The first implementation milestone is the **deterministic kernel**: manifest schema, adapter interface, normalized finding schema, policy states, reports, and test fixtures. CI enforcement and evidence integrity follow next. The opt-in AI assistance layer is added only after the deterministic controls produce trustworthy, redacted findings.

## External scanner adapters

The optional `rules/external-adapters-policy.yaml` profile activates isolated adapters for **Gitleaks 8.30.1** and **Semgrep 1.175.0**. These adapters use only fixed argument lists, temporary report files outside the repository, minimal child-process environments, bounded timeouts, and redacted normalized findings. A missing binary, timeout, malformed report, or scanner error produces `ERROR` and prevents a passing gate.

The external-adapter profile is intentionally opt-in while teams calibrate scanner output. It expects trusted, separately installed scanner binaries matching the declared versions. The standard default profile remains self-contained and preserves the first milestone’s native deterministic controls.

## Development environment

Use the generated `uv.lock` for a reproducible local environment:

```bash
uv sync --frozen --all-extras
uv run before-deploy scan ./target-repository --policy rules/default-policy.yaml
```

## Security principles

The project follows least privilege, isolated execution, explicit policy, fail-closed release behavior for required controls, immutable tool and ruleset versions, redacted evidence, bounded waivers, and developer-reviewed remediation. All repository and external content supplied to an AI assistant is treated as untrusted data.

## Status

The deterministic kernel and isolated Gitleaks/Semgrep adapter foundation are implemented and validated with secure, vulnerable, and fake-tool fixtures. The next increment installs and calibrates the pinned scanner binaries in CI, adds dependency-vulnerability scanning and release provenance verification, then introduces tightly bounded AI assistance.
