"""CLI for running the blinded `find_callers` engineering pilot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from before_deploy.caller_pilot_runner import execute_caller_pilot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="before-deploy-caller-pilot",
        description="Run the gate-neutral static-vs-find_callers engineering pilot.",
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path("fixtures/caller-pilot-v1/cases.json"),
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("fixtures/caller-pilot-v1/corpus.json"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--bridge-command-json",
        required=True,
        help='JSON argv array for the external bridge, e.g. ["python","/abs/adapter.py"].',
    )
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        command = json.loads(args.bridge_command_json)
    except ValueError as error:
        raise SystemExit("--bridge-command-json must be valid JSON") from error
    if not isinstance(command, list):
        raise SystemExit("--bridge-command-json must decode to a JSON array")
    result = execute_caller_pilot(
        cases_path=args.cases,
        corpus_path=args.corpus,
        output_dir=args.output_dir,
        command=command,
        provider=args.provider,
        model=args.model,
        repetitions=args.repetitions,
        timeout_seconds=args.timeout_seconds,
    )
    print(result.pilot_markdown_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
