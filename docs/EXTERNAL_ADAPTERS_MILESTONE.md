# External Scanner Adapters — Milestone 2 Contract

**Status:** Approved for implementation  
**Scope:** Reproducible dependency management, isolated Gitleaks directory scanning, and isolated Semgrep local-rule scanning.  
**Non-goal:** This milestone does not execute user code, scan Git history, upload source or findings, auto-apply fixes, or delegate a release decision to an external tool.

> **Decision:** An external scanner is an untrusted evidence producer. It runs under a fixed adapter contract and may create normalized findings, but only Before Deploy’s deterministic policy engine determines `PASS`, `BLOCK`, `WAIVER_REQUIRED`, or `ERROR`.

## 1. Adapter contract

Each adapter implements the existing `Control` protocol and returns either a fully normalized `ControlResult` or an explicit `ExecutionStatus.ERROR`. It receives only the bounded repository root and a configuration object defined by the checked-in policy. It cannot receive arbitrary user-supplied arguments, an inherited CI environment, arbitrary network configuration, or authority to modify the repository.

| Contract element | Requirement |
|---|---|
| **Executable selection** | The configured executable is resolved once and invoked as an argument list with `shell=False`. The repository path is passed as a literal final argument. |
| **Arguments** | The adapter builds a fixed allowlisted argument vector. No policy field is interpolated into a shell command. |
| **Environment** | The child process receives a minimal environment: `PATH`, locale values, a temporary `HOME`, `NO_COLOR=1`, and scanner-specific privacy flags. CI tokens, cloud credentials, SSH agent variables, and user environment secrets are not propagated. |
| **Working directory** | The scanner uses the repository root as a working directory only where required by its documented CLI behavior. All temporary report files live outside the repository in a restrictive temporary directory. |
| **Timeout** | Every process has a policy-bounded timeout. A timeout is a control `ERROR`, never a clean scan. |
| **Output collection** | JSON is read from a temporary report file or captured standard output, size-bounded, parsed, and normalized. Standard output/stderr is not copied verbatim into reports. |
| **Secrets** | Raw Gitleaks match, secret, line content, and entropy data are never placed in a `Finding`, SARIF, Markdown, JSON, exception, or log message. A normalized finding holds only a tool fingerprint hash, rule ID, redacted path, and line. |
| **Tool health** | Missing executable, process timeout, invalid JSON, output oversize, non-finding nonzero exit, or Semgrep reported error produces `ERROR`. A required adapter error fails the release policy. |
| **Version traceability** | Each execution records the configured tool identity/version string. A future improvement will invoke `--version` at install verification time and bind the exact binary digest in CI. |

## 2. Gitleaks adapter design

Gitleaks supports directory scans, JSON reports, configurable finding exit codes, full redaction, and a command-level timeout.[1] The adapter uses **directory mode only** in this milestone. Its present scan scope is the working tree; Git history scanning remains a separate consented capability because it expands the privacy, execution time, and evidence scope.

```text
gitleaks dir
  --no-banner --no-color --redact=100
  --report-format json --report-path <temporary-report>
  --exit-code 1 --timeout <bounded-seconds>
  <repository-root>
```

| Gitleaks process condition | Normalized adapter result |
|---|---|
| Process exits `0`; report missing or contains `[]`. | `COMPLETED`, zero findings. |
| Process exits configured finding code; valid JSON report contains findings. | `COMPLETED`, one redacted `SEC-SECRET-GITLEAKS-001` finding per record. |
| Process exits nonzero but no valid report exists. | `ERROR`; no inferred finding count. |
| JSON is malformed, exceeds limit, or does not have the expected list shape. | `ERROR`. |
| Binary is unavailable or execution times out. | `ERROR`. |

A Gitleaks report may contain the original secret and matching line; these fields are intentionally discarded after parsing. The canonical normalized fingerprint is computed from the external rule ID, repository-relative path, line number, and upstream fingerprint digest—not from the raw secret.

## 3. Semgrep adapter design

Semgrep `scan` is the documented local, account-free command. Its JSON output is a supported CLI format, and it normally exits successfully even when findings exist unless configured otherwise.[2] [3] The adapter therefore decides finding semantics from validated JSON results rather than relying on an exit code. It uses a **checked-in local rule directory**, disables metrics and version checks, disables autofix, does not enable `--allow-local-builds`, and never invokes a remote registry configuration.

```text
semgrep scan
  --config <checked-in-rule-directory>
  --json --metrics=off --disable-version-check --no-autofix
  --max-target-bytes <bounded-by-policy>
  <repository-root>
```

| Semgrep process condition | Normalized adapter result |
|---|---|
| Process exits `0`, JSON has no results/errors. | `COMPLETED`, zero findings. |
| Process exits `0`, JSON has results and no reported scanner errors. | `COMPLETED`, one normalized `SEC-SAST-SEMGREP-001` finding per result. |
| Process returns nonzero, JSON is invalid, output is too large, or JSON contains scanner errors. | `ERROR`; policy must not report a passing scan. |
| Rule configuration is malformed or missing. | `ERROR`. |
| Binary is unavailable or process times out. | `ERROR`. |

The initial local Semgrep rules supplement—not replace—the native Python AST control. They are enabled through a separate external-adapter policy profile to avoid duplicate release decisions during calibration. Once comparison data is available, a future policy can make Gitleaks and Semgrep the authoritative producers for their control families and retire the bootstrap detectors.

## 4. Policy selection and migration strategy

| Profile | Native controls | External adapters | Intended use |
|---|---|---|---|
| `default-policy.yaml` | Enabled. | Disabled. | Existing local and basic CI behavior; retains the validated first milestone. |
| `external-adapters-policy.yaml` | Core FastAPI/config/dependency controls enabled; bootstrap secret/SAST controls omitted. | Gitleaks and Semgrep enabled and required. | Calibrated CI profile for teams with pinned scanner installations. |
| `strict-policy.yaml` | Existing release controls. | Deferred until adapter calibration and provenance controls are complete. | Existing release design, unchanged by this milestone. |

The policy profile must explicitly select a control. An installed scanner never affects a release merely because it is present on `PATH`.

## 5. Reproducible dependency management

The project will preserve the existing `pyproject.toml` and migrate to `uv.lock`. Local development and CI use `uv sync --frozen --all-extras`, preventing an implicit dependency resolution during verification. The hand-maintained `requirements.lock` bootstrap file is removed after the generated lock has been validated. The project continues to support Python 3.11 and above; it does not unnecessarily lock product users to 3.12.

| Change | Acceptance criterion |
|---|---|
| Add `uv.lock`. | A clean environment installs the application and development dependencies deterministically through `uv sync --frozen --all-extras`. |
| Update CI. | CI installs a pinned `uv`, synchronizes with `--frozen`, and does not invoke unconstrained package resolution. |
| Retain package CLI. | `before-deploy scan` works after a `uv` environment sync. |
| Remove bootstrap lock. | No committed hand-written lockfile remains after `uv.lock` is in use. |

## 6. Test strategy

Tests never need a real scanner binary. A fixture executable is generated inside the test temporary directory and receives only the allowed argument vector. It emits representative Gitleaks report JSON or Semgrep output JSON, including raw secret fields where needed to prove that redaction holds. This verifies parsing, process isolation, errors, timeouts, policy outcomes, and report safety without introducing a real credential into the repository.

| Test class | Required assertion |
|---|---|
| Command construction | The final executable call has no shell string, includes privacy flags, points reports outside the repository, and forbids Semgrep autofix/local builds. |
| Gitleaks normalization | A raw `Secret` value supplied by a fake tool never appears in normalized findings or every output format. |
| Semgrep normalization | JSON rule ID, severity, file path, line, and message become deterministic normalized fields. |
| Failure handling | Missing binary, malformed JSON, timeout, and scanner-reported errors yield `ERROR`; no error case yields `PASS`. |
| Policy integration | The external profile blocks a normalized high-confidence Gitleaks or Semgrep finding. |
| Regression behavior | The existing default profile still passes the secure fixture, blocks the vulnerable fixture, and passes the project self-scan. |

## 7. References

[1]: https://github.com/gitleaks/gitleaks "Gitleaks documentation: directory mode, JSON reports, redaction, exit codes, and timeout"
[2]: https://docs.semgrep.dev/cli-reference "Semgrep CLI reference: local scan flags, JSON output, metric controls, and unsafe local builds"
[3]: https://docs.semgrep.dev/getting-started/cli "Semgrep local scan documentation and exit-code behavior"
