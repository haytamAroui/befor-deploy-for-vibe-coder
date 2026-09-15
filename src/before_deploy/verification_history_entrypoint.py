"""Outer CLI dispatcher for immutable verification history."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.verification_entrypoint import main as verification_main
from before_deploy.verification_history import (
    append_verification_history,
    load_verification_artifact,
    load_verification_history,
    render_verification_history_json,
    render_verification_history_markdown,
    render_verification_history_terminal,
)

HISTORY_INPUT_ERROR_EXIT = 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "history":
        return _history(args[1:])
    if args in (["-h"], ["--help"]):
        exit_code = verification_main(args)
        print("  history             append canonical verification evidence to immutable history")
        return exit_code
    return verification_main(args)


def _history(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy history",
        description=(
            "Append one canonical verification artifact to an immutable linear history. "
            "History is gate-neutral, preserves trust limitations, and does not decide release readiness."
        ),
    )
    parser.add_argument("verification_json", type=Path)
    parser.add_argument("--history-file", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/history"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        verification = load_verification_artifact(args.verification_json)
        previous = load_verification_history(args.history_file) if args.history_file is not None else None
        history = append_verification_history(verification, previous)
        reports = {
            "json": render_verification_history_json(history),
            "markdown": render_verification_history_markdown(history),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "verification-history.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "verification-history.md").write_text(reports["markdown"], encoding="utf-8")
        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_verification_history_terminal(history), end="")
            print(
                f"Verification history: {output_dir / 'verification-history.json'}, "
                f"{output_dir / 'verification-history.md'}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy history: ERROR: {error}", file=sys.stderr)
        return HISTORY_INPUT_ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
