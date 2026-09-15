"""CLI for the gate-neutral independent real-world validation of readiness section 3."""

from __future__ import annotations

import argparse
import sys
from json import dumps
from pathlib import Path
from typing import Sequence

from before_deploy.real_world_validation import (
    REAL_WORLD_AUTHORITY,
    REAL_WORLD_GATE_EFFECT,
    evaluate_real_world_validation,
    load_real_world_run,
    render_real_world_validated_json,
    render_real_world_validated_markdown,
    validate_real_world_benchmark,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="before-deploy-real-world-validation",
        description=(
            "Validate frozen multi-repository corpora and evaluate the section 3 real-world "
            "criteria. Exit codes: 0 pass, 1 criteria not met, 2 input error."
        ),
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument(
        "--run",
        type=Path,
        help="Paired static/exploratory observation record. Validation only when omitted.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("reports/real-world-validation"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        definition = validate_real_world_benchmark(args.manifest, args.repository_root)
        if args.run is None:
            print(
                dumps(
                    {
                        "repositories": [
                            {
                                "commit": item.commit,
                                "known_defects": item.known_defects,
                                "repository_id": item.repository_id,
                                "reviewed_file_count": item.reviewed_file_count,
                            }
                            for item in definition.repositories
                        ],
                        "blinded": definition.blinded,
                        "independent": definition.independent,
                        "known_defects": definition.known_defects,
                        "reviewed_file_count": definition.reviewed_file_count,
                        "authority": REAL_WORLD_AUTHORITY,
                        "gate_effect": REAL_WORLD_GATE_EFFECT,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        static, exploratory = load_real_world_run(args.run)
        result = evaluate_real_world_validation(
            definition, static=static, exploratory=exploratory
        )
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        json_report = render_real_world_validated_json(result)
        markdown_report = render_real_world_validated_markdown(result)
        (output_dir / "real-world-validation.json").write_text(json_report, encoding="utf-8")
        (output_dir / "real-world-validation.md").write_text(markdown_report, encoding="utf-8")
        if args.format == "json":
            print(json_report, end="")
        elif args.format == "markdown":
            print(markdown_report, end="")
        else:
            print(f"Before Deploy real-world validation: {result.name}")
            print(
                f"repositories={result.repository_count} known_defects={result.known_defects} "
                f"detected_defects={result.detected_defects} recall={result.recall:.4f}"
            )
            print(
                f"explore_tp={result.exploration_attributable_tp} "
                f"explore_fp={result.exploration_attributable_fp} "
                f"fp_rate_static={result.static_false_positive_rate:.4f} "
                f"fp_rate_exploratory={result.exploratory_false_positive_rate:.4f}"
            )
            print(f"decision={result.decision}")
            for reason in result.reason_codes:
                print(f"  {reason}")
            print("Authority: BENCHMARK_DIAGNOSTIC, gate_effect=NONE")
            print(
                f"Reports: {output_dir / 'real-world-validation.json'}, "
                f"{output_dir / 'real-world-validation.md'}"
            )
        return 0 if result.decision == "PASS" else 1
    except (OSError, ValueError) as error:
        print(f"before-deploy-real-world-validation: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
