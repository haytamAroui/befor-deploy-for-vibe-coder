"""Outer CLI dispatcher for deterministic verification evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.entrypoint import _load_proposal
from before_deploy.evidence_explanation import DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES
from before_deploy.evidence_investigation import DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES
from before_deploy.human_approval_patch import (
    DEFAULT_MAX_PATCH_RESPONSE_BYTES,
    build_patch_request,
    load_human_approval_artifact,
    load_patch_response,
)
from before_deploy.regression_entrypoint import main as regression_main
from before_deploy.regression_evidence import build_regression_evidence_request
from before_deploy.remediation_proposal import DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES
from before_deploy.verification import (
    build_verification,
    load_patch_materialization_artifact,
    load_patch_materialization_authorization_artifact,
    load_regression_evidence_artifact,
    render_verification_json,
    render_verification_markdown,
    render_verification_terminal,
)

VERIFY_INPUT_ERROR_EXIT = 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "verify":
        return _verify(args[1:])
    if args in (["-h"], ["--help"]):
        exit_code = regression_main(args)
        print("  verify              deterministically evaluate bound regression evidence")
        return exit_code
    return regression_main(args)


def _verify(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy verify",
        description=(
            "Deterministically evaluate the exact remediation verification goals against persisted "
            "hash-verified materialization and regression evidence. Verification is gate-neutral and "
            "does not decide release readiness."
        ),
    )
    parser.add_argument("review_json", type=Path)
    parser.add_argument("selector")
    parser.add_argument("--explanation-response-file", type=Path, required=True)
    parser.add_argument("--investigation-response-file", type=Path)
    parser.add_argument("--proposal-response-file", type=Path, required=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    parser.add_argument("--patch-response-file", type=Path, required=True)
    parser.add_argument("--materialization-authorization-file", type=Path, required=True)
    parser.add_argument("--materialization-file", type=Path, required=True)
    parser.add_argument("--regression-evidence-file", type=Path, required=True)
    parser.add_argument(
        "--max-investigation-response-bytes",
        type=int,
        default=DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES,
    )
    parser.add_argument(
        "--max-explanation-response-bytes",
        type=int,
        default=DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES,
    )
    parser.add_argument(
        "--max-proposal-response-bytes",
        type=int,
        default=DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES,
    )
    parser.add_argument(
        "--max-patch-response-bytes",
        type=int,
        default=DEFAULT_MAX_PATCH_RESPONSE_BYTES,
    )
    parser.add_argument("--output-dir", type=Path, default=Path("reports/verify"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        investigation_request, proposal_request, proposal = _load_proposal(args)
        approval = load_human_approval_artifact(
            args.approval_file,
            proposal,
            proposal_request,
            investigation_request,
        )
        patch_request = build_patch_request(
            proposal,
            proposal_request,
            approval,
            investigation_request,
        )
        patch = load_patch_response(
            args.patch_response_file,
            patch_request,
            proposal_request,
            investigation_request,
            max_bytes=args.max_patch_response_bytes,
        )
        authorization = load_patch_materialization_authorization_artifact(
            args.materialization_authorization_file,
            patch,
            patch_request,
            proposal_request,
            investigation_request,
        )
        materialization = load_patch_materialization_artifact(
            args.materialization_file,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
        )
        regression_request = build_regression_evidence_request(
            materialization,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
        )
        regression = load_regression_evidence_artifact(
            args.regression_evidence_file,
            regression_request,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
        )
        verification = build_verification(
            regression,
            regression_request,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
        )
        reports = {
            "json": render_verification_json(verification),
            "markdown": render_verification_markdown(verification),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "verification.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "verification.md").write_text(reports["markdown"], encoding="utf-8")
        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_verification_terminal(verification), end="")
            print(f"Verification reports: {output_dir / 'verification.json'}, {output_dir / 'verification.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy verify: ERROR: {error}", file=sys.stderr)
        return VERIFY_INPUT_ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
