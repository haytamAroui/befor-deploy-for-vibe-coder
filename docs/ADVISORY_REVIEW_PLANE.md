# Advisory Review Plane

## Purpose

Before Deploy keeps two different kinds of reasoning separate:

1. **Deterministic assurance** — repository evidence, reviewed controls, coverage, policy, waivers, and the final `PolicyDecision`.
2. **Advisory review** — AI or third-party review findings that may help discover bugs, security concerns, performance problems, or maintainability issues.

Only the deterministic `PolicyDecision` is release authority. Advisory findings always carry:

```text
authority = ADVISORY
gate_effect = NONE
```

This is a structural invariant, not a prompt convention.

## `before-deploy review`

`review` runs the normal deterministic scan and optionally imports one or more advisory JSON files:

```bash
uv run before-deploy review /path/to/repo \
  --policy rules/default-policy.yaml \
  --advisory-file /tmp/ocr-result.json \
  --output-dir /tmp/before-deploy-review
```

The command writes the normal deterministic artifacts:

- `report.json`
- `report.md`
- `report.sarif`

and two unified developer-review artifacts:

- `review.json`
- `review.md`

The process exit code is derived from the deterministic `PolicyDecision` exactly as it is for `scan`. Imported advisory findings cannot add a block, remove a block, create a waiver, suppress a finding, or turn `ERROR` into `PASS`.

## Advisory provider runtime

Live advisory execution is provider-independent. `review --ocr` no longer calls OCR directly from the CLI; it constructs an `OcrAdvisoryProvider` and sends an `AdvisoryProviderRequest` through the generic runtime.

Every provider declares a stable identity and returns an `AdvisoryImport`. The runtime catches normal provider exceptions, rejects inconsistent provider identity, validates common scope arguments, and structurally forces every returned finding to:

```text
authority = ADVISORY
gate_effect = NONE
```

Even a malformed provider result that attempts `authority=DETERMINISTIC` or `gate_effect=BLOCK` is normalized back to the advisory boundary before it can enter unified review.

Provider failure becomes an advisory source error rather than a deterministic gate error. `KeyboardInterrupt`, `SystemExit`, and other `BaseException` subclasses are not swallowed.

See [ADVISORY_PROVIDER_RUNTIME.md](ADVISORY_PROVIDER_RUNTIME.md) for the provider interface, failure semantics, identity contract, and staged roadmap.

## Deterministic advisory context

Before any live advisory provider runs, the runtime now prepares or validates a deterministic `AdvisoryContext`.

The selector starts from the provider-independent changed-file scope, materializes exact source bytes, applies per-file and aggregate byte limits, records deterministic exclusions, hashes each selected file, and computes a canonical content-free context digest.

Context metadata is explicitly non-authoritative:

```text
authority = ADVISORY_CONTEXT
gate_effect = NONE
```

Workspace mode uses current working-tree bytes while rejecting symlinked paths. Branch-range and commit modes read bytes from the resolved target Git tree, so context identity does not accidentally depend on unrelated current checkout contents.

Changed files are considered in stable repository-relative path order. Aggregate budgeting includes whole files only; a file that would exceed the remaining budget is excluded as `context_budget` rather than being partially copied.

Successful provider results expose a bounded context summary containing the context digest, selected-file count, selected-byte budget usage, and exclusion count. Full context JSON/Markdown renderers serialize only metadata and hashes, never raw source.

See [ADVISORY_CONTEXT.md](ADVISORY_CONTEXT.md) for the source-byte, hashing, budget, exclusion, and integrity-validation contract.

## OpenCodeReview ingestion

The advisory loader accepts OpenCodeReview JSON emitted by `ocr review --format json`. It supports a top-level array or the common object containers `comments`, `results`, and `issues`.

The importer intentionally retains only bounded review metadata:

- path
- start/end line
- content/message
- category
- severity
- optional confidence

It intentionally discards model-private or raw-code fields such as `thinking`, `existing_code`, and `suggestion_code`. Advisory message content remains untrusted and is not deterministic evidence.

Live OCR execution retains its existing deterministic preflight/final-manifest scope attestation behind `OcrAdvisoryProvider`.

Because OCR currently chooses its own file set rather than directly consuming `AdvisoryContext.files`, the OCR provider now requires its deterministic preview set to equal the bounded context set before OCR starts. A mismatch reports `CONTEXT_LIMITED` and produces no findings. This failure remains gate-neutral.

## Canonical advisory schema

Other review providers can emit this small schema:

```json
{
  "source": {"provider": "example-reviewer"},
  "findings": [
    {
      "finding_id": "EXAMPLE-1",
      "title": "Possible transaction consistency bug",
      "message": "A debit can complete before a later credit fails.",
      "category": "bug",
      "severity": "high",
      "confidence": 0.91,
      "location": {
        "path": "src/payments.py",
        "start_line": 42,
        "end_line": 49
      }
    }
  ]
}
```

Accepted categories are `bug`, `security`, `performance`, `maintainability`, `test`, `style`, `documentation`, and `other`. Accepted severities are `critical`, `high`, `medium`, `low`, and `info`. Unknown values normalize conservatively to `other` / `info` rather than acquiring policy meaning.

## Correlation semantics

Phase 1 correlation is intentionally narrow. An advisory finding is correlated with deterministic findings only when their repository-relative source locations overlap.

A correlation means only:

> these findings refer to overlapping source lines

It does **not** mean the deterministic control proved the AI claim, that the AI confirmed the deterministic finding, or that the advisory finding gains release authority.

Future semantic correlation must remain equally explicit about its evidence contract.

## Benchmark diagnostics

`before-deploy benchmark` evaluates advisory output against a versioned labeled-defect corpus. The benchmark plane is also non-authoritative:

```text
authority = BENCHMARK_DIAGNOSTIC
gate_effect = NONE
```

PR21's matching contract is deterministic: exact repository-relative path, exact normalized category, overlapping source lines, and maximum one-to-one matching. It reports precision, recall, F1, misses, unmatched predictions, and per-category metrics.

PR22 adds the first maintained corpus under `fixtures/review-benchmark-v1/`: four human-curated security issues, four paired secure negative files, exact source-byte provenance, regression-test references, labeling/adjudication rules, an explicit evaluator/provider leakage boundary, and CI validation. Its oracle file is evaluator-only and is not a provider quality result.

See [REVIEW_BENCHMARK.md](REVIEW_BENCHMARK.md) for the corpus/CLI contract and [REVIEW_BENCHMARK_LABELING.md](REVIEW_BENCHMARK_LABELING.md) for labeling rules.

## Architecture sources

This design borrows ideas rather than source code:

- OpenCodeReview's structured findings and deterministic review-selection philosophy inspired a normalized advisory plane.
- The Before Deploy Claude plugin's read-only/reporting boundary inspired the explicit `ADVISORY` / `gate_effect=NONE` contract.

No OpenCodeReview implementation code is copied into Before Deploy. This keeps Before Deploy's MIT codebase independent while allowing architectural learning from the Apache-2.0 project.

## Next increments

The trust-boundary foundation now includes deterministic review scope/preview, isolated OCR execution, scope attestation, review sessions, the deterministic benchmark harness, a provenance-backed seed corpus, a provider-independent advisory runtime, and deterministic content-bound provider context. The next increments are intentionally staged:

1. add provider execution provenance, configuration identity, and budget/timing contracts;
2. build Evidence Graph v1, then semantic correlation, deduplication, and corroboration without authority upgrades;
3. add `inspect`, `investigate`, and `explain` on top of the evidence model;
4. add human-approved remediation, regression evidence, `verify`, and finally explicit `release` assurance.
