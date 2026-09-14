#!/usr/bin/env python3
"""Validate the repository-backed review benchmark corpus and optional oracle fixture."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.review_benchmark import evaluate_advisory_output
from before_deploy.review_benchmark_corpus import validate_benchmark_corpus_provenance


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--oracle-advisory",
        type=Path,
        help="optional evaluator-only advisory fixture that must match every label exactly once",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        validation = validate_benchmark_corpus_provenance(
            args.corpus,
            args.manifest,
            args.repository,
        )
        print(
            "Review benchmark corpus: VALID "
            f"name={validation.name} defects={validation.defect_count} "
            f"positive_files={validation.positive_file_count} "
            f"negative_files={validation.negative_file_count} "
            f"source_commit={validation.source_commit}"
        )

        if args.oracle_advisory is not None:
            result = evaluate_advisory_output(args.corpus, args.oracle_advisory)
            if (
                result.true_positives != validation.defect_count
                or result.false_positives != 0
                or result.false_negatives != 0
            ):
                raise ValueError(
                    "Benchmark oracle no longer matches the corpus exactly: "
                    f"TP={result.true_positives}, FP={result.false_positives}, "
                    f"FN={result.false_negatives}"
                )
            print(
                "Review benchmark oracle: VALID "
                f"TP={result.true_positives} FP=0 FN=0 F1={result.f1:.4f}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"review-benchmark-corpus: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
