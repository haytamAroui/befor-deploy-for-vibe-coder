# Review benchmark seed corpus v1

This directory contains the first provenance-backed Before Deploy review benchmark corpus.

It is intentionally small. The goal of v1 is to establish a trustworthy corpus contract before expanding breadth or comparing model providers.

## Scope

The source scope is declared in `manifest.json` and contains four vulnerable fixtures plus four paired secure fixtures already maintained by the deterministic control test suite:

- FastAPI authentication without an authorization marker;
- FastAPI upload filename passed directly to a filesystem sink;
- destructive Python SQL mutations without a `WHERE` predicate;
- credential-like Python values emitted through logging calls.

The secure companions are part of benchmark scope even though they have no labels. When a provider is evaluated over the declared source scope, findings on those files count as false positives.

## Files

- `corpus.json` — scored ground-truth defects consumed by `before-deploy benchmark`;
- `manifest.json` — source snapshot, exact Git blob IDs, positive/negative roles, label rationale, and evidence-test provenance;
- `oracle-advisory.json` — evaluator-only fixture proving that the corpus and matching contract still line up exactly.

`oracle-advisory.json` is **not** a provider result and must never be used to claim reviewer quality.

## Path convention

All corpus and advisory locations are relative to the root of this repository, not relative to an individual fixture directory. A provider benchmark must preserve those repository-relative paths in its normalized advisory output.

## Leakage boundary

Only the source files listed under `manifest.json.files` are provider input for this corpus. The following are evaluator-only and must not be included in provider context:

- `corpus.json`;
- `manifest.json`;
- `oracle-advisory.json`;
- this README;
- `docs/REVIEW_BENCHMARK_LABELING.md`.

This prevents a reviewer from learning the answers from benchmark metadata.

## Validation

Run:

```bash
uv run python scripts/validate_review_benchmark_corpus.py \
  --repository . \
  --corpus fixtures/review-benchmark-v1/corpus.json \
  --manifest fixtures/review-benchmark-v1/manifest.json \
  --oracle-advisory fixtures/review-benchmark-v1/oracle-advisory.json
```

The validator checks exact current source bytes using Git blob SHA-1 identifiers, verifies that each declared blob is the file stored at the declared source snapshot commit, and then checks label/source consistency, canonical advisory taxonomy, evidence-test selectors, and oracle alignment. The declared snapshot commit therefore must be available in the local Git history; CI uses a full checkout for this offline provenance check.

The Git blob identifier is used only as a deterministic drift and snapshot-membership identifier. It is not treated as a cryptographic trust or authenticity mechanism.
