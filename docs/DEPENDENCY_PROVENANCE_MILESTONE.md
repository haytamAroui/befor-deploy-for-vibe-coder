# Dependency Vulnerability and Provenance Milestone Contract

**Status:** Approved for implementation  
**Scope:** Deterministic dependency-vulnerability evidence for Python repositories and offline GitHub artifact-attestation verification.  
**Non-goals:** Automatic dependency upgrades, Node/Rust/Go vulnerability scanning, release generation, remote authentication forwarding, claiming a SLSA level, or accepting unsigned/unauthenticated provenance.

> **Decision:** Dependency and provenance tools are untrusted evidence producers. Before Deploy uses their structured output only through fixed adapters. The deterministic policy engine remains the only authority that can produce a release decision.

## 1. Control identities and evidence boundaries

| Control | Evidence producer | Policy role | What a successful control establishes | What it does **not** establish |
|---|---|---|---|---|
| `SEC-DEP-VULN-001` | `pip-audit` JSON | Dependency vulnerability gate | The declared Python dependency set was checked against the selected known-vulnerability service at scan time. | Absence of all vulnerabilities, malicious-package detection, exploitability, or non-Python dependency coverage. |
| `SEC-PROVENANCE-001` | `gh attestation verify` JSON | Release-artifact provenance gate | A local artifact was verified against a supplied, cryptographically validated GitHub attestation bundle and pinned expected identity constraints. | A general SLSA level, runtime integrity, or trustworthiness of arbitrary workflow-controlled predicate metadata. |

[pip-audit] documents JSON output, exit code `0` when no known vulnerabilities are found, exit code `1` when known vulnerabilities are found, and explicit audit failure behavior.[1] GitHub’s CLI documents attestation verification against an expected repository/owner and signer identity, with build provenance verified under the `https://slsa.dev/provenance/v1` predicate by default.[2] GitHub notes that signature-certificate data and verified timestamps are independently verifiable, while statement predicate data can be controlled by the producing workflow.[2]

## 2. Dependency-vulnerability adapter

### 2.1 Supported dependency inputs

The adapter supports two deterministic dependency input forms. It never audits the Before Deploy process environment and never installs target-project dependencies.

| Repository evidence | Fixed preparation | `pip-audit` invocation |
|---|---|---|
| An approved `requirements*.txt` file | Use the declared file directly. | `pip-audit --requirement <file> --no-deps --strict --format json --output <temporary-report>` |
| `pyproject.toml` plus `uv.lock` | Call a configured `uv export --locked --no-dev --format requirements-txt --output-file <temporary-requirements>` before the audit. | Run the same `pip-audit` command against the temporary exported requirements file. |

The adapter rejects ambiguous input selection, missing lock evidence, a failed export, an unavailable executable, oversized/invalid JSON, or any exit status other than `0` or `1`. A valid `1` accompanied by valid JSON vulnerability records is a **completed** control with findings, not an adapter error. The fixed command never contains `--fix`, index URLs, ignore lists, or arbitrary user arguments.

### 2.2 Normalized evidence

A normalized vulnerability finding contains the package name, installed version, advisory ID, aliases, and listed fixed versions. It deliberately excludes verbose vulnerability descriptions and tool stderr, because descriptions/logs may be unbounded and are not needed for the release predicate. The finding fingerprint derives from the stable package/version/advisory tuple.

| `pip-audit` condition | Before Deploy execution result |
|---|---|
| Exit `0`, valid JSON, no vulnerability records. | `COMPLETED`, zero findings. |
| Exit `1`, valid JSON, one or more vulnerability records. | `COMPLETED`, one `SEC-DEP-VULN-001` finding per advisory. |
| Exit `0` with nonempty vulnerability records, or exit `1` with none. | `ERROR` because process and structured evidence disagree. |
| Exit outside `{0,1}`, missing executable, export failure, timeout, invalid/oversized JSON. | `ERROR`. |

## 3. Provenance adapter

### 3.1 Offline-bundle mode

The first adapter runs **offline-bundle verification only**. A policy supplies paths, relative to the scanned release directory, for a release artifact and its downloaded GitHub attestation bundle. It also supplies the expected repository and signer workflow identity. No GitHub token, cloud credential, SSH agent, or user-home authentication is exposed to the child process.

```text
gh attestation verify <artifact>
  --bundle <bundle>
  --repo <owner/repository>
  --signer-workflow <owner/repository/.github/workflows/release.yml>
  --predicate-type https://slsa.dev/provenance/v1
  --deny-self-hosted-runners
  --format json
```

The adapter uses the GitHub CLI because it validates signature, expected actor identity, and predicate type. It consumes only the success/failure status and minimal verified-certificate/timestamp presence in JSON output; it does not trust arbitrary fields in the provenance predicate.[2] [3]

| Verification condition | Before Deploy execution result |
|---|---|
| Process exits `0`; JSON is a nonempty list with verification results that include a certificate and verified timestamp. | `COMPLETED`, zero findings, verified evidence metadata only. |
| Process exits nonzero, times out, executable/bundle/artifact is missing, JSON is invalid/oversized, or required verified fields are absent. | `ERROR`. |

A complete provenance verification adds no vulnerability finding. Its evidence is reflected through the completed control execution. If release policy marks `SEC-PROVENANCE-001` required, a failed verification produces `ERROR` and prevents a release pass.

## 4. Process isolation and configuration

Both adapters use the existing isolated process runner: literal argument lists, `shell=False`, `stdin=DEVNULL`, temporary report files outside the scanned repository, a minimal environment, no inherited secret/token variables, bounded report size, and explicit timeouts. Scanner stdout is captured only into a restricted temporary report file; stderr is discarded rather than copied to an application report.

The policy declares executable names, exact expected tool versions for traceability, timeout, maximum report bytes, and only bounded input paths/configuration. It cannot inject arbitrary tool arguments or a shell fragment.

## 5. Release profile and acceptance tests

The `release-evidence-policy.yaml` profile will make SBOM presence, dependency-audit evidence, and provenance evidence required. It is intentionally separate from default/strict-CI profiles because an application repository needs a signed artifact and downloaded attestation bundle before it can satisfy provenance verification.

| Test class | Required acceptance criterion |
|---|---|
| Dependency adapter normalization | A fake pip-audit process returning `1` and valid JSON produces deterministic vulnerability findings without raw tool output. |
| Dependency adapter failure handling | Missing lock evidence, failed `uv export`, invalid JSON, tool timeout, and contradictory exit/report conditions produce `ERROR`. |
| Provenance command construction | The fake `gh` command receives a bundle, expected repo, expected signer workflow, expected SLSA predicate, JSON output flag, and self-hosted-runner denial. |
| Provenance verification | Valid fake verification JSON completes; missing verified certificate/timestamp, malformed JSON, nonzero exit, or missing artifact/bundle produces `ERROR`. |
| Policy integration | Required evidence-control errors cause release `ERROR`; a valid known vulnerability becomes `BLOCK` under the release policy. |
| Regression behavior | Existing default, strict-CI, external-adapter, reports, and fixture tests remain passing. |

## References

[1]: https://github.com/pypa/pip-audit "pip-audit documentation: JSON output, exit codes, strict dependency collection, and security model"
[2]: https://cli.github.com/manual/gh_attestation_verify "GitHub CLI manual: attestation verification, actor identity, verified output, and policy options"
[3]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds "GitHub documentation: generating and verifying artifact attestations"
