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


def main(argv: list[str] | None = None) -> int:
    """Dispatch evidence diagnostics without changing established gate commands."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "inspect":
        return _inspect(args[1:])
    if args and args[0] == "investigate":
        return _investigate(args[1:])
    if args and args[0] == "explain":
        return _explain(args[1:])
    if args and args[0] == "propose":
        return _propose(args[1:])
    if args in (["-h"], ["--help"]):
        print(_top_level_help(), end="")
        return 0
    return legacy_main(args)


def _top_level_help() -> str:
    text = legacy_build_parser().format_help().rstrip()
    return (
        text
        + "\n\nAdditional diagnostic commands:\n"
        + "  inspect             inspect one finding in a persisted review.json without rerunning providers or policy\n"
        + "  investigate         build bounded investigation context and optionally import a structured advisory response\n"
        + "  explain             build cited explanation context and optionally import a structured advisory explanation\n"
        + "  propose             build a cited non-executable remediation proposal from a validated explanation\n"
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
    parser.add_argument("--output-dir", type=Path, default=Path("reports/inspect"), help="directory for inspection.json and inspection.md")
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal", help="format printed to stdout; inspection artifacts are still written")
    args = parser.parse_args(argv)
    try:
        artifact = load_review_evidence(args.review_json)
        result = build_evidence_inspection(artifact, args.selector)
        reports = {"json": render_evidence_inspection_json(result), "markdown": render_evidence_inspection_markdown(result)}
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


def _investigate(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy investigate",
        description=(
            "Build a bounded advisory investigation request from one validated inspection trace and "
            "optionally import a strict structured response. Investigation never changes release policy."
        ),
    )
    parser.add_argument("review_json", type=Path, help="persisted review.json produced by before-deploy review")
    parser.add_argument("selector", help="exact finding node ID, exact finding fingerprint, or advisory finding ID")
    parser.add_argument("--response-file", type=Path, help="optional before-deploy-investigation-v1 JSON response")
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES, help=f"maximum accepted structured investigation response size (default: {DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES})")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/investigate"), help="directory for investigation request/result artifacts")
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal", help="format printed to stdout; investigation artifacts are still written")
    args = parser.parse_args(argv)
    try:
        artifact = load_review_evidence(args.review_json)
        inspection = build_evidence_inspection(artifact, args.selector)
        request = build_evidence_investigation_request(inspection)
        request_reports = {"json": render_evidence_investigation_request_json(request), "markdown": render_evidence_investigation_request_markdown(request)}
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "investigation-request.json").write_text(request_reports["json"], encoding="utf-8")
        (output_dir / "investigation-request.md").write_text(request_reports["markdown"], encoding="utf-8")
        if args.response_file is None:
            if args.format == "json":
                print(request_reports["json"], end="")
            elif args.format == "markdown":
                print(request_reports["markdown"], end="")
            else:
                print(render_evidence_investigation_request_terminal(request), end="")
                print(f"Investigation request: {output_dir / 'investigation-request.json'}, {output_dir / 'investigation-request.md'}")
            return 0
        result = load_evidence_investigation_response(args.response_file, request, max_bytes=args.max_response_bytes)
        reports = {"json": render_evidence_investigation_json(result), "markdown": render_evidence_investigation_markdown(result)}
        (output_dir / "investigation.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "investigation.md").write_text(reports["markdown"], encoding="utf-8")
        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_evidence_investigation_terminal(result), end="")
            print(f"Investigation reports: {output_dir / 'investigation.json'}, {output_dir / 'investigation.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy investigate: ERROR: {error}", file=sys.stderr)
        return INVESTIGATE_INPUT_ERROR_EXIT


def _explain(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy explain",
        description=(
            "Build bounded explanation context from validated inspection and optional investigation content, "
            "then optionally import a cited advisory explanation. Explanation never changes release policy."
        ),
    )
    parser.add_argument("review_json", type=Path, help="persisted review.json produced by before-deploy review")
    parser.add_argument("selector", help="exact finding node ID, exact finding fingerprint, or advisory finding ID")
    parser.add_argument("--investigation-response-file", type=Path, help="optional before-deploy-investigation-v1 response used as bounded explanation context")
    parser.add_argument("--response-file", type=Path, help="optional before-deploy-explanation-v1 JSON response")
    parser.add_argument("--max-investigation-response-bytes", type=int, default=DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES, help=f"maximum accepted investigation response size (default: {DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES})")
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES, help=f"maximum accepted explanation response size (default: {DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES})")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/explain"), help="directory for explanation request/result artifacts")
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal", help="format printed to stdout; explanation artifacts are still written")
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
            if args.format == "json":
                print(request_reports["json"], end="")
            elif args.format == "markdown":
                print(request_reports["markdown"], end="")
            else:
                print(render_evidence_explanation_request_terminal(request), end="")
                print(f"Explanation request: {output_dir / 'explanation-request.json'}, {output_dir / 'explanation-request.md'}")
            return 0
        result = load_evidence_explanation_response(args.response_file, request, investigation_request, max_bytes=args.max_response_bytes)
        reports = {"json": render_evidence_explanation_json(result), "markdown": render_evidence_explanation_markdown(result)}
        (output_dir / "explanation.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "explanation.md").write_text(reports["markdown"], encoding="utf-8")
        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_evidence_explanation_terminal(result), end="")
            print(f"Explanation reports: {output_dir / 'explanation.json'}, {output_dir / 'explanation.md'}")
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy explain: ERROR: {error}", file=sys.stderr)
        return EXPLAIN_INPUT_ERROR_EXIT


def _propose(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy propose",
        description=(
            "Build a non-executable remediation proposal request from a validated explanation and "
            "optionally import a strict proposal response. Proposals never mutate code or approve patches."
        ),
    )
    parser.add_argument("review_json", type=Path, help="persisted review.json produced by before-deploy review")
    parser.add_argument("selector", help="exact finding node ID, exact finding fingerprint, or advisory finding ID")
    parser.add_argument("--explanation-response-file", type=Path, required=True, help="required before-deploy-explanation-v1 response")
    parser.add_argument("--investigation-response-file", type=Path, help="investigation response used when the explanation was built with investigation context")
    parser.add_argument("--response-file", type=Path, help="optional before-deploy-remediation-proposal-v1 JSON response")
    parser.add_argument("--max-investigation-response-bytes", type=int, default=DEFAULT_MAX_INVESTIGATION_RESPONSE_BYTES)
    parser.add_argument("--max-explanation-response-bytes", type=int, default=DEFAULT_MAX_EXPLANATION_RESPONSE_BYTES)
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_REMEDIATION_RESPONSE_BYTES)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/propose"), help="directory for remediation proposal request/result artifacts")
    parser.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal", help="format printed to stdout; proposal artifacts are still written")
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
        request = build_remediation_proposal_request(
            explanation_request,
            explanation,
            investigation_request,
        )
        request_reports = {
            "json": render_remediation_proposal_request_json(request),
            "markdown": render_remediation_proposal_request_markdown(request),
        }
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "remediation-proposal-request.json").write_text(request_reports["json"], encoding="utf-8")
        (output_dir / "remediation-proposal-request.md").write_text(request_reports["markdown"], encoding="utf-8")
        if args.response_file is None:
            if args.format == "json":
                print(request_reports["json"], end="")
            elif args.format == "markdown":
                print(request_reports["markdown"], end="")
            else:
                print(render_remediation_proposal_request_terminal(request), end="")
                print(
                    f"Remediation proposal request: {output_dir / 'remediation-proposal-request.json'}, "
                    f"{output_dir / 'remediation-proposal-request.md'}"
                )
            return 0
        result = load_remediation_proposal_response(
            args.response_file,
            request,
            investigation_request,
            max_bytes=args.max_response_bytes,
        )
        reports = {
            "json": render_remediation_proposal_json(result),
            "markdown": render_remediation_proposal_markdown(result),
        }
        (output_dir / "remediation-proposal.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "remediation-proposal.md").write_text(reports["markdown"], encoding="utf-8")
        if args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(render_remediation_proposal_terminal(result), end="")
            print(
                f"Remediation proposal reports: {output_dir / 'remediation-proposal.json'}, "
                f"{output_dir / 'remediation-proposal.md'}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"before-deploy propose: ERROR: {error}", file=sys.stderr)
        return PROPOSE_INPUT_ERROR_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
