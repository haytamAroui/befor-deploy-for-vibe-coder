# Review Benchmark Harness

## Purpose

`before-deploy benchmark` measures advisory review output against a human-labeled defect corpus without granting the reviewer any release authority.

The harness is deliberately deterministic. Given the same corpus and advisory JSON, it produces the same one-to-one matching and the same precision, recall, and F1 metrics. Benchmark quality is diagnostic only:

```text
authority = BENCHMARK_DIAGNOSTIC
gate_effect = NONE
```

A high benchmark score cannot create a release approval, remove a deterministic block, create a waiver, or otherwise modify the deterministic `PolicyDecision`.

## CLI

```bash
uv run before-deploy benchmark \
  --corpus /path/to/corpus.json \
  --advisory-file /path/to/reviewer-output.json \
  --output-dir reports/benchmark
```

The command accepts Before Deploy advisory JSON and OpenCodeReview-compatible JSON. It writes:

- `benchmark.json` for machine consumption;
- `benchmark.md` for human review.

`--format terminal`, `--format json`, and `--format markdown` control stdout only. Artifacts are always written after successful evaluation.

A successful benchmark evaluation exits `0`, regardless of the measured score. Invalid or unreadable benchmark/advisory input exits `2`. That exit status represents benchmark input failure, not a release gate decision.

## Corpus schema v1

A corpus is a versioned JSON document:

```json
{
  "schema_version": 1,
  "benchmark": {
    "name": "example-corpus-v1",
    "defects": [
      {
        "id": "BUG-001",
        "path": "src/payments.py",
        "start_line": 42,
        "end_line": 49,
        "category": "bug",
        "severity": "high"
      }
    ]
  }
}
```

Validation is intentionally strict for the fields that affect scoring:

- `schema_version` must be `1`;
- `benchmark.name` must be non-empty text;
- `benchmark.defects` must be an array;
- defect IDs must be unique;
- paths must be repository-relative and may not contain parent traversal;
- line numbers must be positive integers;
- `end_line` may not precede `start_line`;
- `category` must be non-empty text.

`severity` is optional metadata in v1. It is retained in the corpus model but does not participate in matching.

## Matching contract

The v1 matching contract is:

```text
exact_path + exact_category + line_overlap + one_to_one
```

A prediction is eligible to match a labeled defect only when:

1. its normalized repository-relative path exactly equals the labeled path;
2. its normalized category exactly equals the labeled category; and
3. its predicted line range overlaps the labeled line range.

Predictions without a source line cannot match line-level ground truth.

The harness then computes a deterministic maximum-cardinality bipartite matching. Each labeled defect can match at most one prediction, and each prediction can match at most one labeled defect. Duplicate predictions therefore increase false positives rather than inflating recall.

This contract is intentionally narrower than semantic correlation. PR21 measures location/category detection quality; semantic deduplication, corroboration, and evidence-graph reasoning belong to later stages.

## Metrics

The harness reports overall and per-category:

- true positives (`TP`);
- false positives (`FP`);
- false negatives (`FN`);
- precision;
- recall;
- F1.

Definitions are standard:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
```

When both the corpus and prediction set are empty, precision, recall, and F1 are reported as `1.0`: the reviewer produced no false alarms and missed no labeled defects.

## CI smoke fixture

`fixtures/review-benchmark/` contains a tiny synthetic corpus and advisory result used only to prove that the command, parsing, matching, reporting, and artifact-writing path work in CI.

It is **not** the public or product benchmark corpus and must not be used to make reviewer-quality claims. A real labeled corpus with provenance, labeling rules, and benchmark CI is a separate follow-up increment.

## Future measurements

The current harness establishes deterministic detection scoring only. Future benchmark versions may add provider execution measurements such as latency and token/cost budgets, and later remediation/verification measurements, while keeping those measurements separate from deterministic release authority.
