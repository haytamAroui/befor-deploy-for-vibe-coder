"""Outer CLI dispatcher for controlled patch materialization and regression evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.entrypoint import _load_proposal
from before_deploy.entrypoint import main as evidence_main
from before_deploy.human_approval_patch import (
    DEFAULT_MAX_PATCH_RESPONSE_BYTES,
    build_patch_request,
    load_human_approval_artifact,
    load_patch_response,
)
from before_deploy.regression_evidence import (
    DEFAULT_MAX_REGRESSION_RESPONSE_BYTES,
    build_patch_materialization_authorization,
    build_regression_evidence_request,
    load_regression_evidence_response,
    materialize_patch,
    render_patch_materialization_authorization_json,
    render_patch_materialization_authorization_markdown,
    render_patch_materialization_json,
    render_patch_materialization_markdown,
    render_patch_materialization_terminal,
    render_regression_evidence_json,
    render_regression_evidence_markdown,
    render_regression_evidence_request_json,
    render_regression_evidence_request_markdown,
    render_regression_evidence_request_terminal,
    render_regression_evidence_terminal,
)
from before_deploy.evidence_explanation import DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES
from before_deploy.evidence_investigation import DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES
from before_deploy.remediation_proposal import DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES

REGRESS_INPUT_ERROR_EXIT = 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "regress":
        return _regress(args[1:])
    if args in (["-h"], ["--help"]):
        exit_code = evidence_main(args)
        print("  regress             materialize one exact patch and bind regression evidence")
        return exit_code
    return evidence_main(args)


def _regress(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy regress",
        description=(
            "Materialize one exact approved patch after explicit patch-digest confirmation, verify "
            "pre/post content hashes, and optionally import regression observations. This workflow "
            "does not change PolicyDecision or authorize release."
        ),
    )
    parser.add_argument("review_json", type=Path)
    parser.add_argument("selector")
    parser.add_argument("--explanation-response-file", type=Path, required=True)
    parser.add_argument("--investigation-response-file", type=Path)
    parser.add_argument("--proposal-response-file", type=Path, required=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    parser.add_argument("--patch-response-file", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--confirm-patch-sha256", required=True)
    parser.add_argument("--operator", required=True, help="declared human operator authorizing exact patch materialization")
    parser.add_argument("--regression-response-file", type=Path)
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
    parser.add_argument(
        "--max-regression-response-bytes",
        type=int,
        default=DEFAULT_MAX_REGRESSION_RESPONSE_BYTES,
    )
    parser.add_argument("--output-dir", type=Path, default=Path("reports/regress"))
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
        authorization = build_patch_materialization_authorization(
            patch,
            patch_request,
            proposal_request,
            investigation_request,
            confirmed_patch_sha256=args.confirm_patch_sha256,
            operator=args.operator,
        )
        materialization = materialize_patch(
            args.repository,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
        )
        request = build_regression_evidence_request(
            materialization,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
        )

        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        authorization_json = render_patch_materialization_authorization_json(authorization)
        authorization_markdown = render_patch_materialization_authorization_markdown(authorization)
        materialization_json = render_patch_materialization_json(materialization)
        materialization_markdown = render_patch_materialization_markdown(materialization)
        request_json = render_regression_evidence_request_json(request)
        request_markdown = render_regression_evidence_request_markdown(request)
        (output_dir / "patch-materialization-authorization.json").write_text(authorization_json, encoding="utf-8")
        (output_dir / "patch-materialization-authorization.md").write_text(authorization_markdown, encoding="utf-8")
        (output_dir / "patch-materialization.json").write_text(materialization_json, encoding="utf-8")
        (output_dir / "patch-materialization.md").write_text(materialization_markdown, encoding="utf-8")
        (output_dir / "regression-evidence-request.json").write_text(request_json, encoding="utf-8")
        (output_dir / "regression-evidence-request.md").write_text(request_markdown, encoding="utf-8")

        if args.regression_response_file is None:
            reports = {"json": request_json, "markdown": request_markdown}
            _print_format(args.format, reports, render_regression_evidence_request_terminal(request))
            if args.format == "terminal":
                print(render_patch_materialization_terminal(materialization), end="")
                print(
                    f"Regression request: {output_dir / 'regression-evidence-request.json'}, "
                    f"{output_dir / 'regression-evidence-request.md'}"
                )
            return 0

        result = load_regression_evidence_response(
            args.regression_response_file,
            request,
            patch,
            patch_request,
            authorization,
            proposal_request,
            investigation_request,
            max_bytes=args.max_regression_response_bytes,
        )
        reports = {
            "json": render_regression_evidence_json(result),
            "markdown": render_regression_evidence_markdown(result),
        }
        (output_dir / "regression-evidence.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "regression-evidence.md").write_text(reports["markdown"], encoding="utf-8")
        _print_format(args.format, reports, render_regression_evidence_terminal(result))
        if args.format == "terminal":
            print(render_patch_materialization_terminal(materialization), end="")
            print(
                f"Regression evidence: {output_dir / 'regression-evidence.json'}, "
                f"{output_dir / 'regression-evidence.md'}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy regress: ERROR: {error}", file=sys.stderr)
        return REGRESS_INPUT_ERROR_EXIT


def _print_format(format_name: str, reports: dict[str, str], terminal: str) -> None:
    if format_name == "json":
        print(reports["json"], end="")
    elif format_name == "markdown":
        print(reports["markdown"], end="")
    else:
        print(terminal, end="")


if __name__ == "__main__":
    raise SystemExit(main())
