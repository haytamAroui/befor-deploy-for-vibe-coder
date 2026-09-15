"""CLI for gate-neutral comparative advisory benchmark experiments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.comparative_benchmark import (
    evaluate_comparative_manifest,
    render_comparative_json,
    render_comparative_markdown,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy-benchmark-compare",
        description="Compare repeated advisory-review variants without changing release authority.",
    )
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/benchmark-compare"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        result = evaluate_comparative_manifest(args.corpus, args.manifest)
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        json_report = render_comparative_json(result)
        markdown_report = render_comparative_markdown(result)
        (output_dir / "comparative-benchmark.json").write_text(json_report, encoding="utf-8")
        (output_dir / "comparative-benchmark.md").write_text(markdown_report, encoding="utf-8")
        if args.format == "json":
            print(json_report, end="")
        elif args.format == "markdown":
            print(markdown_report, end="")
        else:
            print(f"Before Deploy comparative benchmark: {result.name}")
            for variant in result.variants:
                print(
                    f"{variant.variant}: role={variant.variant_role} runs={variant.run_count} "
                    f"precision={variant.mean_precision:.4f} recall={variant.mean_recall:.4f} "
                    f"f1={variant.mean_f1:.4f} explore_tp={variant.exploration_attributable_tp} "
                    f"explore_fp={variant.exploration_attributable_fp} stability={variant.prediction_stability:.4f}"
                )
            print("Authority: BENCHMARK_DIAGNOSTIC, gate_effect=NONE")
            print(
                f"Reports: {output_dir / 'comparative-benchmark.json'}, "
                f"{output_dir / 'comparative-benchmark.md'}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy-benchmark-compare: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
