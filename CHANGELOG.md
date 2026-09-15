# Changelog

All notable changes to **Preflight** (`before-deploy`) are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-15

### Added

- **Dual CLI Surface**:
  - `preflight` primary command alias alongside backwards-compatible `before-deploy`.
  - `preflight-mcp` Model Context Protocol entrypoint alongside `before-deploy-mcp`.
- **Deterministic Static Security Scanners**:
  - Multi-language AST, regex, and config scanners covering Python, Next.js Server Actions, JavaScript/TypeScript, Docker Compose, Go, Rust, PHP, and Ruby.
  - Core rules covering SQL injection, command execution boundaries, authentication/authorization checks, SSRF risks, and sensitive data leakage.
- **Cryptographic Provenance & Evidence Lineage**:
  - Full git repository and policy digest computation (`SHA-256`).
  - Tamper-evident scan manifests with deterministic fingerprints.
  - Multi-format report generation: Industry-standard **SARIF v2.1.0**, Markdown, and JSON.
- **Policy Enforcement & Waiver Controls**:
  - Strict CI policy evaluation (`rules/strict-ci-policy.yaml`) and configurable policy bundles.
  - Structured waiver mechanisms requiring explicit reason codes and expiration tracking.
- **Bounded AI Advisory Plane**:
  - External reviewer bridge with isolated subprocess execution.
  - Bounded turns, timeout enforcement (120s), and strict `gate_effect=NONE` advisory separation.
  - Subprocess bridge stderr logging and observability during caller pilot execution.
- **Model Context Protocol (MCP) Server**:
  - Exposes tools for scan execution, report inspection, and policy evaluation to AI coding assistants.
- **Benchmark Evaluation Suite**:
  - Precision, recall, and F1 scoring against verified ground-truth corpora.
  - Synthetic and seed review benchmarks validated with deterministic oracles.
- **CI/CD Integrations**:
  - Official GitHub Action (`action.yml`) for one-line workflow integration (`uses: haytamAroui/preflight@v1`).
  - Pre-commit hook configuration (`.pre-commit-hooks.yaml`).
  - Automated release workflow with distribution packaging (`.github/workflows/release.yml`).
