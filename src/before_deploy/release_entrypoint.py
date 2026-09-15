"""Outer CLI dispatcher for deterministic release disposition."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.inventory import DEFAULT_MAX_FILE_BYTES
from before_deploy.release_disposition import (
    ReleaseRequirements,
    assess_release_snapshot,
    build_release_disposition,
    load_policy_release_evidence,
    load_release_materialization,
    render_release_disposition_json,
    render_release_disposition_markdown,
    render_release_disposition_terminal,
)
from before_deploy.verification_history import load_verification_history
from before_deploy.verification_history_entrypoint import main as history_main

RELEASE_NOT_READY_EXIT = 1
RELEASE_ERROR_EXIT = 2
RELEASE_INPUT_ERROR_EXIT = 3


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "release":
        return _release(args[1:])
    if args in (["-h"], ["--help"]):
        exit_code = history_main(args)
        print("  release             decide final release disposition from deterministic evidence")
        return exit_code
    return history_main(args)


def _release(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy release",
        description=(
            "Produce the authoritative deterministic release disposition from persisted policy evidence, "
            "the current verification selected by immutable history, and the current workspace snapshot. "
            "No LLM or advisory provider participates in the decision."
        ),
    )
    parser.add_argument("policy_report_json", type=Path)
    parser.add_argument("--verification-history-file", type=Path, required=True)
    parser.add_argument("--materialization-file", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--require-attested-evidence", action="store_true")
    parser.add_argument("--require-reviewed-patch", action="store_true")
    parser.add_argument("--require-reviewed-materialization", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/release"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        policy = load_policy_release_evidence(args.policy_report_json)
        history = load_verification_history(args.verification_history_file)
        materialization = load_release_materialization(args.materialization_file, history)
        snapshot = assess_release_snapshot(
            args.repository,
            policy,
            materialization,
            max_file_bytes=args.max_file_bytes,
        )
        disposition = build_release_disposition(
            policy,
            history,
            materialization,
            snapshot,
            requirements=ReleaseRequirements(
                require_attested_evidence=args.require_attested_evidence,
                require_reviewed_patch=args.require_reviewed_patch,
                require_reviewed_materialization=args.require_reviewed_materialization,
            ),
        )
        reports = {
            "json": render_release_disposition_json(disposition),
            "markdown": render_release_disposition_markdown(disposition),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "release-disposition.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "release-disposition.md").write_text(reports["markdown"], encoding="utf-8")
        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_release_disposition_terminal(disposition), end="")
            print(
                f"Release disposition: {output_dir / 'release-disposition.json'}, "
                f"{output_dir / 'release-disposition.md'}"
            )
        if disposition.status == "READY":
            return 0
        if disposition.status in ("HOLD", "BLOCK"):
            return RELEASE_NOT_READY_EXIT
        return RELEASE_ERROR_EXIT
    except (OSError, ValueError) as error:
        print(f"before-deploy release: ERROR: {error}", file=sys.stderr)
        return RELEASE_INPUT_ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
