"""Command-line interface for deterministic pre-deployment scans."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.controls.dependency_audit import DependencyAuditControl
from before_deploy.controls.external import ExternalToolConfig
from before_deploy.controls.gitleaks import GitleaksControl
from before_deploy.controls.gosec import GosecControl
from before_deploy.controls.go_vulnerabilities import GoVulnerabilitySnapshotControl
from before_deploy.controls.provenance import ProvenanceControl
from before_deploy.controls.semgrep import SemgrepControl
from before_deploy.controls.trivy_config import TrivyConfigControl
from before_deploy.models import GateOutcome
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy
from before_deploy.reports import render_json, render_markdown, render_sarif

EXIT_CODES = {
    GateOutcome.PASS: 0,
    GateOutcome.NOT_EVALUATED: 0,
    GateOutcome.BLOCK: 10,
    GateOutcome.WAIVER_REQUIRED: 11,
    GateOutcome.ERROR: 20,
}


def build_parser() -> argparse.ArgumentParser:
    """Create the stable CLI argument interface."""
    parser = argparse.ArgumentParser(
        prog="before-deploy",
        description="Run deterministic pre-deployment security controls.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a repository and apply a policy profile")
    scan.add_argument("repository", type=Path, help="repository directory to scan")
    scan.add_argument(
        "--policy",
        type=Path,
        default=Path("rules/default-policy.yaml"),
        help="policy YAML file (default: rules/default-policy.yaml)",
    )
    scan.add_argument("--waivers", type=Path, help="optional narrowly scoped waiver YAML file")
    scan.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="directory for report.json, report.md, and report.sarif",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        help="maximum included file size in bytes (default: 1000000)",
    )
    scan.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "sarif"),
        default="terminal",
        help="format printed to stdout; all report files are still written",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute the CLI and return a CI-friendly exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    parser.error(f"Unsupported command: {args.command}")
    return 20


def _controls_for_profile(profile, policy_path: Path):
    controls = list(native_controls())
    if "SEC-SECRET-GITLEAKS-001" in profile.controls:
        settings = profile.tools.get("gitleaks")
        if settings is None:
            raise ValueError("Policy enables Gitleaks but does not configure external_tools.gitleaks")
        controls.append(
            GitleaksControl(
                ExternalToolConfig(
                    executable=settings.executable,
                    tool_version=settings.version,
                    timeout_seconds=settings.timeout_seconds,
                    max_report_bytes=settings.max_report_bytes,
                )
            )
        )
    if "SEC-GOSEC-001" in profile.controls:
        settings = profile.tools.get("gosec")
        if settings is None:
            raise ValueError("Policy enables Gosec but does not configure external_tools.gosec")
        controls.append(
            GosecControl(
                ExternalToolConfig(
                    executable=settings.executable,
                    tool_version=settings.version,
                    timeout_seconds=settings.timeout_seconds,
                    max_report_bytes=settings.max_report_bytes,
                )
            )
        )
    if "SEC-GO-VULN-001" in profile.controls:
        controls.append(GoVulnerabilitySnapshotControl())
    if "SEC-TRIVY-CONFIG-001" in profile.controls:
        settings = profile.tools.get("trivy")
        if settings is None:
            raise ValueError("Policy enables Trivy configuration scanning but lacks external_tools.trivy")
        controls.append(
            TrivyConfigControl(
                ExternalToolConfig(
                    executable=settings.executable,
                    tool_version=settings.version,
                    timeout_seconds=settings.timeout_seconds,
                    max_report_bytes=settings.max_report_bytes,
                )
            )
        )
    if "SEC-DEP-VULN-001" in profile.controls:
        settings = profile.tools.get("pip_audit")
        if settings is None or profile.dependency_audit is None:
            raise ValueError(
                "Policy enables dependency auditing but lacks external_tools.pip_audit or dependency_audit"
            )
        uv_settings = profile.tools.get("uv")
        if profile.dependency_audit.input_kind == "uv_lock" and uv_settings is None:
            raise ValueError("Policy uses uv_lock dependency audit but does not configure external_tools.uv")
        uv_config = (
            ExternalToolConfig(
                executable=uv_settings.executable,
                tool_version=uv_settings.version,
                timeout_seconds=uv_settings.timeout_seconds,
                max_report_bytes=uv_settings.max_report_bytes,
            )
            if uv_settings is not None
            else None
        )
        controls.append(
            DependencyAuditControl(
                ExternalToolConfig(
                    executable=settings.executable,
                    tool_version=settings.version,
                    timeout_seconds=settings.timeout_seconds,
                    max_report_bytes=settings.max_report_bytes,
                ),
                audit_policy=profile.dependency_audit,
                uv_config=uv_config,
            )
        )
    if "SEC-PROVENANCE-001" in profile.controls:
        settings = profile.tools.get("gh")
        if settings is None or profile.provenance is None:
            raise ValueError(
                "Policy enables provenance verification but lacks external_tools.gh or provenance"
            )
        controls.append(
            ProvenanceControl(
                ExternalToolConfig(
                    executable=settings.executable,
                    tool_version=settings.version,
                    timeout_seconds=settings.timeout_seconds,
                    max_report_bytes=settings.max_report_bytes,
                ),
                provenance_policy=profile.provenance,
            )
        )
    if "SEC-SAST-SEMGREP-001" in profile.controls:
        settings = profile.tools.get("semgrep")
        if settings is None:
            raise ValueError("Policy enables Semgrep but does not configure external_tools.semgrep")
        controls.append(
            SemgrepControl(
                ExternalToolConfig(
                    executable=settings.executable,
                    tool_version=settings.version,
                    timeout_seconds=settings.timeout_seconds,
                    max_report_bytes=settings.max_report_bytes,
                ),
                rule_directory=policy_path.parent / "semgrep",
            )
        )
    return tuple(controls)


def _scan(args: argparse.Namespace) -> int:
    try:
        profile = load_policy(args.policy)
        controls = configured_controls(profile, _controls_for_profile(profile, args.policy))
        result = ScanOrchestrator(controls).scan(
            args.repository,
            args.policy,
            waiver_path=args.waivers,
            max_file_bytes=args.max_file_bytes,
        )
        output_dir = args.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        reports = {
            "json": render_json(result),
            "markdown": render_markdown(result),
            "sarif": render_sarif(result),
        }
        (output_dir / "report.json").write_text(reports["json"], encoding="utf-8")
        (output_dir / "report.md").write_text(reports["markdown"], encoding="utf-8")
        (output_dir / "report.sarif").write_text(reports["sarif"], encoding="utf-8")

        if args.format == "terminal":
            _print_terminal_summary(result, output_dir)
        elif args.format == "json":
            print(reports["json"], end="")
        elif args.format == "markdown":
            print(reports["markdown"], end="")
        else:
            print(reports["sarif"], end="")
        return EXIT_CODES[result.decision.outcome]
    except (OSError, ValueError) as error:
        print(f"before-deploy: ERROR: {error}", file=sys.stderr)
        return EXIT_CODES[GateOutcome.ERROR]


def _print_terminal_summary(result, output_dir: Path) -> None:
    outcome = result.decision.outcome.value
    print(f"Before Deploy: {outcome}")
    print(f"Scan ID: {result.manifest.scan_id}")
    print(f"Repository digest: {result.manifest.repository_digest}")
    print(
        "Findings: "
        f"block={len(result.decision.blocking_fingerprints)}, "
        f"waiver_required={len(result.decision.waiver_required_fingerprints)}, "
        f"advisory={len(result.decision.advisory_fingerprints)}, "
        f"waived={len(result.decision.waived_fingerprints)}"
    )
    if result.decision.error_control_ids:
        print("Control errors: " + ", ".join(result.decision.error_control_ids))
    print(f"Reports: {output_dir / 'report.json'}, {output_dir / 'report.md'}, {output_dir / 'report.sarif'}")


if __name__ == "__main__":
    raise SystemExit(main())
