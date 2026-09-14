# OpenCodeReview Advisory Adapter

## Purpose

Before Deploy can optionally run OpenCodeReview (OCR) as a **non-authoritative advisory reviewer** while keeping the deterministic Before Deploy policy engine as the only release authority.

The adapter exists to gain OCR-style broad bug discovery without allowing an LLM review result to issue `PASS`, remove a block, create a waiver, suppress a deterministic finding, or mutate policy.

## Provider runtime boundary

Live OCR execution is now reached through the generic advisory-provider runtime:

```text
before-deploy review --ocr
        |
        v
OcrAdvisoryProvider
        |
        v
execute_advisory_provider(...)
        |
        v
bounded OCR adapter
```

The provider runtime owns the common authority boundary and structurally forces returned findings to `authority=ADVISORY` and `gate_effect=NONE`. It also converts normal provider exceptions, invalid provider identity, and malformed provider-result status into advisory source errors rather than deterministic gate failures.

OCR-specific process isolation and scope attestation remain in this adapter. The lower-level `run_ocr_advisory(...)` function remains an implementation-level compatibility surface; CLI orchestration no longer calls it directly.

See [ADVISORY_PROVIDER_RUNTIME.md](ADVISORY_PROVIDER_RUNTIME.md) for the provider-independent contract.

## Usage

Workspace review:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --ocr \
  --output-dir /tmp/before-deploy-review
```

Branch-range review:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --ocr \
  --from main \
  --to HEAD \
  --output-dir /tmp/before-deploy-review
```

Single-commit review:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --ocr \
  --commit abc123 \
  --output-dir /tmp/before-deploy-review
```

The legacy `--ocr-from`, `--ocr-to`, and `--ocr-commit` spellings remain accepted as aliases.

OCR must already be installed and configured separately. Enabling `--ocr` may send repository code to the LLM provider configured in OpenCodeReview. The flag is therefore explicit opt-in and is never enabled by a Before Deploy policy profile.

## Fixed execution contract

The adapter resolves only the executable named `ocr` from `PATH` and invokes it without a shell. It does not accept an arbitrary executable path or arbitrary extra command arguments.

Before the LLM review, Before Deploy computes its own deterministic changed-file preview using the same review mode and `--max-file-bytes`. OCR is then asked for its own machine-readable `--preview`. OCR may review a subset of Before Deploy's allowed paths, but it may not expand beyond them.

Only after that preflight succeeds does the adapter run the actual OCR review with the equivalent fixed command shape:

```text
ocr review \
  --repo <repository> \
  --audience agent \
  --format json \
  --output <temporary-file>
```

The adapter may additionally append one reviewed diff mode:

```text
--from <ref> --to <ref>
```

or:

```text
--commit <ref>
```

Those modes are mutually exclusive, and `--from` / `--to` must be supplied together.

Repository paths and refs are passed as discrete process arguments rather than interpolated into a shell command. They are still inputs to OCR and Git and are not treated as deterministic security evidence by Before Deploy.

## Scope attestation

OCR scope is checked in two stages.

### 1. Preflight

Before Deploy builds the provider-independent review preview and treats its `will_review=true` paths as the maximum allowed advisory scope. OCR's `--preview --format json` selection is compared against that set before any LLM review starts.

If OCR selects a path outside the Before Deploy set:

```text
status = ERROR
scope_status = EXPANDED
findings = []
```

The actual OCR review is not started.

OCR is allowed to select fewer files than Before Deploy. That is visible as:

```text
scope_status = PARTIAL
```

rather than being mistaken for complete advisory coverage.

### 2. Final run manifest

Current OCR versions can emit the versioned `ocr.run-manifest/v1` manifest. When that supported manifest is present, Before Deploy compares `manifest.coverage.selected[].path` with the OCR preflight selection.

Possible scope states are:

| State | Meaning |
|---|---|
| `MATCHED` | OCR selected exactly the deterministic allowed set. |
| `PARTIAL` | OCR reviewed a strict subset of the allowed set. |
| `PREFLIGHT_ONLY` | Preflight was checked, but final OCR output did not expose the supported run-manifest. |
| `EXPANDED` | OCR selected at least one path outside the deterministic allowed set. Findings are discarded. |
| `DRIFT` | OCR's final selected set changed from its preflight set. Findings are discarded. |
| `INVALID_MANIFEST` | The supported OCR manifest was present but malformed. Findings are discarded. |
| `NOT_CHECKED` | No scope attestation completed, typically because OCR failed earlier. |

Scope attestation is **diagnostic only**. It can reject or discard untrusted OCR findings, but it cannot create a deterministic `BLOCK`, `PASS`, waiver, or policy result.

This asymmetry is deliberate: advisory data may be rejected for violating its contract, but advisory success or failure never becomes release authority.

## Isolation and bounds

The adapter:

- invokes OCR without a shell;
- does not concatenate repository content or refs into a shell command;
- disables stdin;
- discards OCR stdout;
- discards OCR stderr rather than importing provider/tool diagnostics into assurance artifacts;
- forces OCR preview and review JSON into a temporary directory;
- applies a bounded preflight timeout and a default 900-second review timeout;
- accepts at most 2,000,000 bytes of each OCR JSON artifact by default;
- normalizes findings through the existing advisory loader;
- discards OCR `thinking`, `existing_code`, and `suggestion_code` fields from the unified assurance view.

The timeout and maximum accepted JSON size may be narrowed or expanded explicitly with:

```text
--ocr-timeout-seconds
--ocr-max-output-bytes
```

The JSON size setting is an **acceptance limit checked after OCR returns**, not an operating-system filesystem quota while OCR is running. It prevents oversized OCR output from entering the unified assurance model, but it does not claim to cap temporary-file growth during the external OCR process.

## Failure semantics

OCR is advisory, so OCR failure is also advisory.

If OCR is missing, times out, exits non-zero, produces no result, exceeds the accepted size limit, emits unusable JSON, violates the deterministic scope, drifts after preflight, or emits a malformed supported manifest, Before Deploy records an advisory source error and discards OCR findings.

The generic provider runtime adds a second containment boundary around the adapter: a normal uncaught provider exception or malformed provider result is also converted to an advisory source error.

The deterministic scan still owns the process exit code. For example, if the deterministic decision is `PASS` and OCR times out or fails scope attestation, the release decision remains `PASS`; the unified review clearly reports the OCR source error. Conversely, OCR success can never override a deterministic `BLOCK` or `ERROR`.

This avoids two authority leaks: an optional AI outage cannot become an implicit release gate, and an advisory provider cannot silently widen its review scope beyond Before Deploy's deterministic selection contract.

## Outputs

`before-deploy review` continues to write the deterministic artifacts:

- `report.json`
- `report.md`
- `report.sarif`

and the unified advisory artifacts:

- `review.json`
- `review.md`

Each advisory source includes status, finding count, bounded error message, `scope_status`, and a bounded `scope_message` when applicable. Raw OCR stdout/stderr and model-private fields are not copied into these artifacts.

## Trust boundary

```text
Before Deploy deterministic preview
              |
        maximum allowed scope
              |
              v
         OCR preflight
              |
       no scope expansion
              |
              v
         OCR LLM review
              |
       final manifest check
              |
              v
     provider runtime
              |
      ADVISORY findings
      gate_effect = NONE
              |
              v
        Unified review view

    ------------------------- trust boundary

      Before Deploy controls
              |
              v
       PolicyDecision
              |
      PASS/BLOCK/ERROR
```

The adapter is a discovery integration, not part of the deterministic trust base.
