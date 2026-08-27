# Isolated Trivy calibration corpus

This corpus prepares a manual calibration of `SEC-TRIVY-CONFIG-001`. It does not download any binary, checks bundle, or vulnerability database, and the automated tests do not invoke Trivy. Its files are minimal static inputs for an independently provisioned **Trivy 0.74.0** binary in an approved air-gapped environment; they are not executable application code.

> This calibration preparation does not make the adapter required on a protected branch. The versioned deterministic policy engine remains the sole release authority.

## Matrix

| Directory | Inputs within the adapter scope | Calibration purpose | Expectation before approval |
|---|---|---|---|
| `secure/` | `Dockerfile`, `main.tf` | Nominal minimal configuration without deliberately unsafe settings | No normalized finding is anticipated, but the real result must be reviewed because embedded checks can change. |
| `vulnerable/` | `Dockerfile`, `main.tf` | Simple Dockerfile weaknesses and an S3 bucket without hardening options | At least one relevant Dockerfile or Terraform finding is anticipated; observed IDs and their stability must be recorded during calibration. |
| `ambiguous/` | `main.tf` | Value depending on an unresolved Terraform data source | No strict verdict is predeclared. This case measures static-analysis limits and must never be treated as cloud-state evidence. |
| `suppression/` | `main.tf` plus `.trivyignore` | Target-controlled `trivy:ignore:` comment and ignore file | The inline comment must be neutralized in the staged copy and `.trivyignore` must be absent from that copy. Any finding remains subject only to an exact Before Deploy waiver. |
| `unsupported/` | `compose.yaml`, `terraform.tfvars` | Explicitly out-of-scope formats | No input may be staged and the adapter must return `NOT_APPLICABLE` without starting a binary. |

The vulnerable Dockerfile uses an image tagged `latest` and omits a `USER` instruction. Trivy documentation notes that a Dockerfile without `USER` can raise `AVD-DS-0002`. The Terraform suppression fixture uses `AVD-AWS-0089`, an identifier Trivy documents as an inline-ignore example. These identifiers are **calibration landmarks**, not promises that every Trivy version, embedded bundle, or configuration will emit them. [1]

## Future calibration procedure

A real calibration is intentionally a distinct human step. It can begin only after Trivy `0.74.0` has been provisioned independently on a runner with no network egress and its distribution provenance verified. Do not install or download Trivy from this repository, a fixture, or a calibration workflow.

| Step | Required evidence | Rejection condition |
|---|---|---|
| 1. Establish the runner | Preinstalled binary, verified distribution digest/provenance, and environment-level egress isolation | A workflow downloaded the binary, the version differs, or connectivity is uncontrolled. |
| 2. Inspect invocation | Capture the adapter-built command: `config`, `misconfig`, `dockerfile,terraform`, `offline-scan`, and no checks/data/tfvars/registry options | Any target-supplied option, extra scanner, custom check, module fetch, or registry access. |
| 3. Run each directory separately | Retain only Before Deploy’s **normalized, redacted** report and execution metadata | Retention of Trivy stdout/stderr, source content, URLs, causes, or resource IDs. |
| 4. Compare the matrix | Review observed IDs, categories, lines, severities, and `NOT_APPLICABLE`; record deviations and false positives | Treating no finding as security proof, or Terraform ambiguity as cloud state. |
| 5. Approve separately | Human review of calibration, redaction, false positives/negatives, and the air-gapped environment; a separate reviewed policy change | Automatically adding Trivy to strict CI or a protected branch. |

Trivy documents that Terraform analysis is static, cannot resolve provider calls behind data sources, and can leave computed attributes unknown. The `ambiguous/` inputs exist to keep that limitation visible. [2]

## Automated checks included

The Python tests in this repository use only fake executables. They verify the matrix inventory, allowed-file staging, rejection of unsupported inputs, suppression neutralization, path confinement, redaction, version checking, and fail-closed errors. Real Trivy results are not simulated as a successful calibration.

## References

[1]: https://trivy.dev/docs/latest/guide/scanner/misconfiguration/config/config/ "Trivy — misconfiguration configuration and inline ignores"
[2]: https://trivy.dev/docs/latest/guide/coverage/iac/terraform/ "Trivy — Terraform analysis limitations"
