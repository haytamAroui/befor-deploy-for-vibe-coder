# OpenCodeReview Advisory Adapter

## Purpose

Before Deploy can optionally run OpenCodeReview (OCR) as a **non-authoritative advisory reviewer** while keeping the deterministic Before Deploy policy engine as the only release authority.

The adapter exists to gain OCR-style broad bug discovery without allowing an LLM review result to issue `PASS`, remove a block, create a waiver, suppress a deterministic finding, or mutate policy.

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
  --ocr-from main \
  --ocr-to HEAD \
  --output-dir /tmp/before-deploy-review
```

Single-commit review:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --ocr \
  --ocr-commit abc123 \
  --output-dir /tmp/before-deploy-review
```

OCR must already be installed and configured separately. Enabling `--ocr` may send repository code to the LLM provider configured in OpenCodeReview. The flag is therefore explicit opt-in and is never enabled by a Before Deploy policy profile.

## Fixed execution contract

The adapter resolves only the executable named `ocr` from `PATH` and invokes it without a shell. It does not accept an arbitrary executable path or arbitrary extra command arguments.

The fixed command shape is equivalent to:

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

## Isolation and bounds

The adapter:

- invokes OCR without a shell;
- does not concatenate repository content or refs into a shell command;
- disables stdin;
- discards OCR stdout;
- discards OCR stderr rather than importing provider/tool diagnostics into assurance artifacts;
- forces OCR JSON output into a temporary directory;
- applies a default 900-second wall-clock timeout;
- accepts at most 2,000,000 bytes of OCR JSON by default;
- normalizes the result through the existing advisory loader;
- discards OCR `thinking`, `existing_code`, and `suggestion_code` fields from the unified assurance view.

The timeout and maximum accepted JSON size may be narrowed or expanded explicitly with:

```text
--ocr-timeout-seconds
--ocr-max-output-bytes
```

The JSON size setting is an **acceptance limit checked after OCR returns**, not an operating-system filesystem quota while OCR is running. It prevents oversized OCR output from entering the unified assurance model, but it does not claim to cap temporary-file growth during the external OCR process.

## Failure semantics

OCR is advisory, so OCR failure is also advisory.

If OCR is missing, times out, exits non-zero, produces no result, exceeds the accepted size limit, or emits unusable JSON, Before Deploy records an advisory source with:

```text
status = ERROR
findings = []
```

The deterministic scan still owns the process exit code. For example, if the deterministic decision is `PASS` and OCR times out, the release decision remains `PASS`; the unified review clearly reports the OCR source error. Conversely, OCR success can never override a deterministic `BLOCK` or `ERROR`.

This avoids a subtle authority leak where an optional AI service outage would otherwise become an implicit release gate.

## Outputs

`before-deploy review` continues to write the deterministic artifacts:

- `report.json`
- `report.md`
- `report.sarif`

and the unified advisory artifacts:

- `review.json`
- `review.md`

Each advisory source includes its status, finding count, and a bounded error message when applicable. Raw OCR stdout/stderr and model-private fields are not copied into these artifacts.

## Trust boundary

The architecture is intentionally asymmetric:

```text
OpenCodeReview / other advisory engines
              |
              v
      ADVISORY findings
      gate_effect = NONE
              |
              v
        Unified review view
              |
    ------------------------- trust boundary
              |
              v
      Before Deploy controls
              |
              v
       PolicyDecision
              |
      PASS/BLOCK/ERROR
```

The adapter is a discovery integration, not part of the deterministic trust base.
