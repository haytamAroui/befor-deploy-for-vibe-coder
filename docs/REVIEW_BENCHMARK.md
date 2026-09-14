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

The benchmark loader validates the fields that affect scoring:

- `schema_version` must be `1`;
- `benchmark.name` must be non-empty text;
- `benchmark.defects` must be an array;
- defect IDs must be unique;
- paths must be repository-relative and may not contain parent traversal;
- line numbers must be positive integers;
- `end_line` may not precede `start_line`;
- `category` must be non-empty text.

`severity` is optional metadata in v1. It is retained in the corpus model but does not participate in matching.

Maintained Before Deploy corpora apply an additional provenance validator. It restricts category/severity values to the canonical advisory taxonomy, pins source bytes, and requires label/test provenance. This keeps the generic harness usable for third-party corpora while making the first-party corpus stricter.

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

This contract is intentionally narrower than semantic correlation. The benchmark measures location/category detection quality; semantic deduplication, corroboration, and evidence-graph reasoning belong to later stages.

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

## Maintained seed corpus v1

`fixtures/review-benchmark-v1/` is the first maintained, provenance-backed corpus. It is deliberately small and security-focused so the corpus contract can stabilize before provider comparisons expand it.

The scope contains four vulnerable source fixtures and four paired secure fixtures covering:

- FastAPI authorization declaration;
- FastAPI upload filename handling;
- destructive Python SQL without a predicate;
- sensitive Python values sent to logging.

The four maintained labels are human-curated root-cause issues. Existing deterministic regression tests are cited as supporting provenance, but scanner finding count does not generate benchmark labels automatically. The destructive-SQL and sensitive-logging cases deliberately consolidate adjacent same-root-cause statements into one benchmark issue each.

See `docs/REVIEW_BENCHMARK_LABELING.md` for the labeling and adjudication contract.

## Provenance manifest

`fixtures/review-benchmark-v1/manifest.json` records:

- source repository and snapshot commit;
- every provider-input source file;
- positive/negative role;
- exact Git blob SHA-1 for drift detection;
- label path/range/category/severity;
- supporting deterministic control ID;
- exact regression-test selector;
- human-readable rationale.

The Git blob identifier is a byte-level reproducibility check, not a cryptographic trust claim.

Validate it with:

```bash
uv run python scripts/validate_review_benchmark_corpus.py \
  --repository . \
  --corpus fixtures/review-benchmark-v1/corpus.json \
  --manifest fixtures/review-benchmark-v1/manifest.json \
  --oracle-advisory fixtures/review-benchmark-v1/oracle-advisory.json
```

Validation fails if a pinned source changes, a positive/negative role drifts, a label no longer matches `corpus.json`, a label uses a non-canonical category/severity, or its cited regression test disappears.

## Leakage boundary

A valid provider run receives only the source files declared by the manifest, plus future bounded context selected under the provider/context contract.

Ground truth, rationale, the oracle advisory, benchmark reports, and labeling documentation are evaluator-only. A run that exposes them to the reviewer is contaminated and must not be used for score claims.

`oracle-advisory.json` is only a harness sentinel: CI requires it to match every maintained label exactly once. It is not an AI/provider result and is not a quality baseline.

## CI fixtures

Two levels now run in CI:

1. `fixtures/review-benchmark/` remains a tiny synthetic command smoke fixture.
2. `fixtures/review-benchmark-v1/` is the maintained provenance-backed seed corpus. CI validates its provenance/oracle contract and produces a benchmark artifact from the oracle sentinel.

Neither CI path turns a benchmark score into release authority. Provider-quality thresholds are intentionally not part of the deterministic release gate.

## Reporting limits

The seed corpus is too small and too narrow to support broad reviewer-quality claims. Any comparative result should identify the corpus version, provider/model/runtime, configuration/context contract, revision/date, and raw TP/FP/FN in addition to precision/recall/F1.

## Future measurements

The current harness establishes deterministic detection scoring and corpus provenance. Future benchmark versions may add provider execution measurements such as latency and token/cost budgets, and later remediation/verification measurements, while keeping those measurements separate from deterministic release authority.
