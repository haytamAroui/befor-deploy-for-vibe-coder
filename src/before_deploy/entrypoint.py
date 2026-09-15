"""Installed command dispatcher, including persisted evidence inspection."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.cli import build_parser as legacy_build_parser
from before_deploy.cli import main as legacy_main
from before_deploy.evidence_artifact import load_review_evidence
from before_deploy.evidence_inspect import (
    build_evidence_inspection,
    render_evidence_inspection_json,
    render_evidence_inspection_markdown,
    render_evidence_inspection_terminal,
)

INSPECT_INPUT_ERROR_EXIT = 2


def main(argv: list[str] | None = None) -> int:
    """Dispatch inspect without changing the established scan/review/benchmark parser."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "inspect":
        return _inspect(args[1:])
    if args in (["-h"], ["--help"]):
        print(_top_level_help(), end="")
        return 0
    return legacy_main(args)


def _top_level_help() -> str:
    text = legacy_build_parser().format_help().rstrip()
    return (
        text
        + "\n\nAdditional diagnostic command:\n"
        + "  inspect             inspect one finding in a persisted review.json without rerunning providers or policy\n"
    )


def _inspect(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy inspect",
        description=(
            "Inspect one persisted deterministic or advisory finding and its validated evidence lineage. "
            "Inspection never reruns a scan, provider, or release policy."
        ),
    )
    parser.add_argument("review_json", type=Path, help="persisted review.json produced by before-deploy review")
    parser.add_argument(
        "selector",
        help="exact finding node ID, exact finding fingerprint, or advisory finding ID",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/inspect"),
        help="directory for inspection.json and inspection.md",
    )
    parser.add_argument(
        "--format",
        choices=("terminal", "json", "markdown"),
        default="terminal",
        help="format printed to stdout; inspection artifacts are still written",
    )
    args = parser.parse_args(argv)

    try:
        artifact = load_review_evidence(args.review_json)
        result = build_evidence_inspection(artifact, args.selector)
        reports = {
            "json": render_evidence_inspection_json(result),
            "markdown": render_evidence_inspection_markdown(result),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "inspection.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "inspection.md").write_text(reports["markdown"], encoding="utf-8")

        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_evidence_inspection_terminal(result), end="")
            print(f"Inspection reports: {output_dir / 'inspection.json'}, {output_dir / 'inspection.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy inspect: ERROR: {error}", file=sys.stderr)
        return INSPECT_INPUT_ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
