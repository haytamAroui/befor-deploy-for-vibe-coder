"""Installed command dispatcher for persisted evidence diagnostics."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.cli import build_parser as legacy_build_parser
from before_deploy.cli import main as legacy_main
from before_deploy.evidence_artifact import load_review_evidence
from before_deploy.evidence_explanation import (
    DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES,
    build_evidence_explanation_request,
    load_evidence_explanation_response,
    render_evidence_explanation_json,
    render_evidence_explanation_markdown,
    render_evidence_explanation_request_json,
    render_evidence_explanation_request_markdown,
    render_evidence_explanation_request_terminal,
    render_evidence_explanation_terminal,
)
from before_deploy.evidence_inspect import (
    build_evidence_inspection,
    render_evidence_inspection_json,
    render_evidence_inspection_markdown,
    render_evidence_inspection_terminal,
)
from before_deploy.evidence_investigation import (
    DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES,
    build_evidence_investigation_request,
    load_evidence_investigation_response,
    render_evidence_investigation_json,
    render_evidence_investigation_markdown,
    render_evidence_investigation_request_json,
    render_evidence_investigation_request_markdown,
    render_evidence_investigation_request_terminal,
    render_evidence_investigation_terminal,
)
from before_deploy.human_approval_patch import (
    DEFAULT_MAX_PATCH_RESPONSE_BYTES,
    build_human_approval,
    build_patch_request,
    load_human_approval_artifact,
    load_patch_response,
    render_human_approval_json,
    render_human_approval_markdown,
    render_human_approval_terminal,
    render_patch_json,
    render_patch_markdown,
    render_patch_request_json,
    render_patch_request_markdown,
    render_patch_request_terminal,
    render_patch_terminal,
)
from before_deploy.remediation_proposal import (
    DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES,
    build_remediation_proposal_request,
    load_remediation_proposal_response,
    render_remediation_proposal_json,
    render_remediation_proposal_markdown,
    render_remediation_proposal_request_json,
    render_remediation_proposal_request_markdown,
    render_remediation_proposal_request_terminal,
    render_remediation_proposal_terminal,
)

INSPECT_INPUT_ERROR_EXIT = 2
INVESTIGATE_INPUT_ERROR_EXIT = 2
EXPLAIN_INPUT_ERROR_EXIT = 2
PROPOSE_INPUT_ERROR_EXIT = 2
APPROVE_INPUT_ERROR_EXIT = 2
FIX_INPUT_ERROR_EXIT = 2


def main(argv: list[str] | None = None) -> int:
    """Dispatch evidence workflows without changing established gate commands."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "inspect":
        return _inspect(args[1:])
    if args and args[0] == "investigate":
        return _investigate(args[1:])
    if args and args[0] == "explain":
        return _explain(args[1:])
    if args and args[0] == "propose":
        return _propose(args[1:])
    if args and args[0] == "approve":
        return _approve(args[1:])
    if args and args[0] == "fix":
        return _fix(args[1:])
    if args in (["-h"], ["--help"]):
        print(_top_level_help(), end="")
        return 0
    return legacy_main(args)


def _top_level_help() -> str:
    text = legacy_build_parser().format_help().rstrip()
    return (
        text
        + "\n\nAdditional evidence workflow commands:\n"
        + "  inspect             inspect one persisted finding and its evidence lineage\n"
        + "  investigate         build bounded investigation context and import advisory investigation\n"
        + "  explain             build cited explanation context and import advisory explanation\n"
        + "  propose             build a cited non-executable remediation proposal\n"
        + "  approve             explicitly approve or reject one exact remediation proposal digest\n"
        + "  fix                 build an approved patch request and optionally import a patch artifact\n"
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
    parser.add_argument("selector", help="exact finding node ID, exact finding fingerprint, or advisory finding ID")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/inspect"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
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
        _print_format(args.format, reports, render_evidence_inspection_terminal(result))
        if args.format == "terminal":
            print(f"Inspection reports: {output_dir / 'inspection.json'}, {output_dir / 'inspection.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy inspect: ERROR: {error}", file=sys.stderr)
        return INSPECT_INPUT_ERROR_EXIT


def _investigate(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy investigate",
        description="Build bounded investigation context and optionally import an advisory response.",
    )
    parser.add_argument("review_json", type=Path)
    parser.add_argument("selector")
    parser.add_argument("--response-file", type=Path)
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES,
    )
    parser.add_argument("--output-dir", type=Path, default=Path("reports/investigate"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        artifact = load_review_evidence(args.review_json)
        inspection = build_evidence_inspection(artifact, args.selector)
        request = build_evidence_investigation_request(inspection)
        request_reports = {
            "json": render_evidence_investigation_request_json(request),
            "markdown": render_evidence_investigation_request_markdown(request),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "investigation-request.json").write_text(request_reports["json"], encoding="utf-8")
        (output_dir / "investigation-request.md").write_text(request_reports["markdown"], encoding="utf-8")
        if args.response_file is None:
            _print_format(
                args.format,
                request_reports,
                render_evidence_investigation_request_terminal(request),
            )
            if args.format == "terminal":
                print(
                    f"Investigation request: {output_dir / 'investigation-request.json'}, "
                    f"{output_dir / 'investigation-request.md'}"
                )
            return 0
        result = load_evidence_investigation_response(
            args.response_file,
            request,
            max_bytes=args.max_response_bytes,
        )
        reports = {
            "json": render_evidence_investigation_json(result),
            "markdown": render_evidence_investigation_markdown(result),
        }
        (output_dir / "investigation.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "investigation.md").write_text(reports["markdown"], encoding="utf-8")
        _print_format(args.format, reports, render_evidence_investigation_terminal(result))
        if args.format == "terminal":
            print(f"Investigation reports: {output_dir / 'investigation.json'}, {output_dir / 'investigation.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy investigate: ERROR: {error}", file=sys.stderr)
        return INVESTIGATE_INPUT_ERROR_EXIT


def _explain(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy explain",
        description="Build bounded explanation context and optionally import a cited advisory explanation.",
    )
    parser.add_argument("review_json", type=Path)
    parser.add_argument("selector")
    parser.add_argument("--investigation-response-file", type=Path)
    parser.add_argument("--response-file", type=Path)
    parser.add_argument(
        "--max-investigation-response-bytes",
        type=int,
        default=DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES,
    )
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/explain"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        artifact = load_review_evidence(args.review_json)
        inspection = build_evidence_inspection(artifact, args.selector)
        investigation_request = build_evidence_investigation_request(inspection)
        investigation = None
        if args.investigation_response_file is not None:
            investigation = load_evidence_investigation_response(
                args.investigation_response_file,
                investigation_request,
                max_bytes=args.max_investigation_response_bytes,
            )
        request = build_evidence_explanation_request(inspection, investigation_request, investigation)
        request_reports = {
            "json": render_evidence_explanation_request_json(request),
            "markdown": render_evidence_explanation_request_markdown(request),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "explanation-request.json").write_text(request_reports["json"], encoding="utf-8")
        (output_dir / "explanation-request.md").write_text(request_reports["markdown"], encoding="utf-8")
        if args.response_file is None:
            _print_format(args.format, request_reports, render_evidence_explanation_request_terminal(request))
            if args.format == "terminal":
                print(
                    f"Explanation request: {output_dir / 'explanation-request.json'}, "
                    f"{output_dir / 'explanation-request.md'}"
                )
            return 0
        result = load_evidence_explanation_response(
            args.response_file,
            request,
            investigation_request,
            max_bytes=args.max_response_bytes,
        )
        reports = {
            "json": render_evidence_explanation_json(result),
            "markdown": render_evidence_explanation_markdown(result),
        }
        (output_dir / "explanation.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "explanation.md").write_text(reports["markdown"], encoding="utf-8")
        _print_format(args.format, reports, render_evidence_explanation_terminal(result))
        if args.format == "terminal":
            print(f"Explanation reports: {output_dir / 'explanation.json'}, {output_dir / 'explanation.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy explain: ERROR: {error}", file=sys.stderr)
        return EXPLAIN_INPUT_ERROR_EXIT


def _propose(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy propose",
        description="Build a non-executable remediation proposal from a validated explanation.",
    )
    _add_proposal_lineage_arguments(parser, require_proposal=False)
    parser.add_argument("--response-file", type=Path)
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/propose"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        investigation_request, _, _, proposal_request = _build_proposal_request(args)
        request_reports = {
            "json": render_remediation_proposal_request_json(proposal_request),
            "markdown": render_remediation_proposal_request_markdown(proposal_request),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "remediation-proposal-request.json").write_text(request_reports["json"], encoding="utf-8")
        (output_dir / "remediation-proposal-request.md").write_text(request_reports["markdown"], encoding="utf-8")
        if args.response_file is None:
            _print_format(
                args.format,
                request_reports,
                render_remediation_proposal_request_terminal(proposal_request),
            )
            if args.format == "terminal":
                print(
                    f"Remediation proposal request: {output_dir / 'remediation-proposal-request.json'}, "
                    f"{output_dir / 'remediation-proposal-request.md'}"
                )
            return 0
        proposal = load_remediation_proposal_response(
            args.response_file,
            proposal_request,
            investigation_request,
            max_bytes=args.max_response_bytes,
        )
        reports = {
            "json": render_remediation_proposal_json(proposal),
            "markdown": render_remediation_proposal_markdown(proposal),
        }
        (output_dir / "remediation-proposal.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "remediation-proposal.md").write_text(reports["markdown"], encoding="utf-8")
        _print_format(args.format, reports, render_remediation_proposal_terminal(proposal))
        if args.format == "terminal":
            print(
                f"Remediation proposal reports: {output_dir / 'remediation-proposal.json'}, "
                f"{output_dir / 'remediation-proposal.md'}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy propose: ERROR: {error}", file=sys.stderr)
        return PROPOSE_INPUT_ERROR_EXIT


def _approve(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy approve",
        description=(
            "Create explicit workflow approval/rejection for one validated remediation proposal. "
            "Approval authorizes patch generation only and never changes release policy."
        ),
    )
    _add_proposal_lineage_arguments(parser, require_proposal=True)
    parser.add_argument("--decision", choices=("APPROVE", "REJECT"), required=True)
    parser.add_argument("--approver", required=True, help="declared human approver identity")
    parser.add_argument("--confirm-proposal-sha256", required=True)
    parser.add_argument("--rationale")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/approve"))
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    args = parser.parse_args(argv)
    try:
        investigation_request, proposal_request, proposal = _load_proposal(args)
        approval = build_human_approval(
            proposal,
            proposal_request,
            investigation_request,
            decision=args.decision,
            approver=args.approver,
            confirmed_proposal_sha256=args.confirm_proposal_sha256,
            rationale=args.rationale,
        )
        reports = {
            "json": render_human_approval_json(approval),
            "markdown": render_human_approval_markdown(approval),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "human-approval.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "human-approval.md").write_text(reports["markdown"], encoding="utf-8")
        _print_format(args.format, reports, render_human_approval_terminal(approval))
        if args.format == "terminal":
            print(f"Approval reports: {output_dir / 'human-approval.json'}, {output_dir / 'human-approval.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy approve: ERROR: {error}", file=sys.stderr)
        return APPROVE_INPUT_ERROR_EXIT


def _fix(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy fix",
        description=(
            "Build a patch-generation request for an explicitly approved proposal and optionally import "
            "a scoped patch artifact. The patch is never applied by this command."
        ),
    )
    _add_proposal_lineage_arguments(parser, require_proposal=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    parser.add_argument("--patch-response-file", type=Path)
    parser.add_argument("--max-patch-response-bytes", type=int, default=DEFAULT_MAX_PATCH_RESPONSE_BYTES)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/fix"))
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
        request = build_patch_request(
            proposal,
            proposal_request,
            approval,
            investigation_request,
        )
        request_reports = {
            "json": render_patch_request_json(request),
            "markdown": render_patch_request_markdown(request),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "patch-request.json").write_text(request_reports["json"], encoding="utf-8")
        (output_dir / "patch-request.md").write_text(request_reports["markdown"], encoding="utf-8")
        if args.patch_response_file is None:
            _print_format(args.format, request_reports, render_patch_request_terminal(request))
            if args.format == "terminal":
                print(f"Patch request: {output_dir / 'patch-request.json'}, {output_dir / 'patch-request.md'}")
            return 0
        patch = load_patch_response(
            args.patch_response_file,
            request,
            proposal_request,
            investigation_request,
            max_bytes=args.max_patch_response_bytes,
        )
        reports = {"json": render_patch_json(patch), "markdown": render_patch_markdown(patch)}
        (output_dir / "patch.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "patch.md").write_text(reports["markdown"], encoding="utf-8")
        _print_format(args.format, reports, render_patch_terminal(patch))
        if args.format == "terminal":
            print(f"Patch reports: {output_dir / 'patch.json'}, {output_dir / 'patch.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy fix: ERROR: {error}", file=sys.stderr)
        return FIX_INPUT_ERROR_EXIT


def _add_proposal_lineage_arguments(parser: argparse.ArgumentParser, *, require_proposal: bool) -> None:
    parser.add_argument("review_json", type=Path)
    parser.add_argument("selector")
    parser.add_argument("--explanation-response-file", type=Path, required=True)
    parser.add_argument("--investigation-response-file", type=Path)
    if require_proposal:
        parser.add_argument("--proposal-response-file", type=Path, required=True)
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
    if require_proposal:
        parser.add_argument(
            "--max-proposal-response-bytes",
            type=int,
            default=DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES,
        )


def _build_proposal_request(args: argparse.Namespace):
    artifact = load_review_evidence(args.review_json)
    inspection = build_evidence_inspection(artifact, args.selector)
    investigation_request = build_evidence_investigation_request(inspection)
    investigation = None
    if args.investigation_response_file is not None:
        investigation = load_evidence_investigation_response(
            args.investigation_response_file,
            investigation_request,
            max_bytes=args.max_investigation_response_bytes,
        )
    explanation_request = build_evidence_explanation_request(
        inspection,
        investigation_request,
        investigation,
    )
    explanation = load_evidence_explanation_response(
        args.explanation_response_file,
        explanation_request,
        investigation_request,
        max_bytes=args.max_explanation_response_bytes,
    )
    proposal_request = build_remediation_proposal_request(
        explanation_request,
        explanation,
        investigation_request,
    )
    return investigation_request, explanation_request, explanation, proposal_request


def _load_proposal(args: argparse.Namespace):
    investigation_request, _, _, proposal_request = _build_proposal_request(args)
    proposal = load_remediation_proposal_response(
        args.proposal_response_file,
        proposal_request,
        investigation_request,
        max_bytes=args.max_proposal_response_bytes,
    )
    return investigation_request, proposal_request, proposal


def _print_format(format_name: str, reports: dict[str, str], terminal: str) -> None:
    if format_name == "json":
        print(reports["json"], end="")
    elif format_name == "markdown":
        print(reports["markdown"], end="")
    else:
        print(terminal, end="")


if __name__ == "__main__":
    raise SystemExit(main())
