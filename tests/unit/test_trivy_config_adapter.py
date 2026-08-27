import json
from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.external import ExternalToolConfig
from before_deploy.controls.trivy_config import TrivyConfigControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus
from before_deploy.reports import render_json, render_markdown, render_sarif


def _context(repository: Path) -> ControlContext:
    repository.mkdir()
    (repository / "app.py").write_text("print('safe')\n", encoding="utf-8")
    return ControlContext(repository_root=repository, inventory=collect_inventory(repository))


def _refreshed_context(repository: Path) -> ControlContext:
    return ControlContext(repository_root=repository, inventory=collect_inventory(repository))


def _fake_tool(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | 0o111)
    return path


def test_trivy_config_stages_supported_files_uses_fixed_offline_arguments_and_redacts(
    tmp_path, monkeypatch
):
    context = _context(tmp_path / "repository")
    (context.repository_root / "Dockerfile").write_text(
        "# trivy:ignore:DS001\nFROM ubuntu:latest\nUSER root\n", encoding="utf-8"
    )
    (context.repository_root / "infra.tf").write_text(
        "resource \"aws_s3_bucket\" \"example\" {}\n", encoding="utf-8"
    )
    (context.repository_root / ".trivyignore").write_text("DS001\n", encoding="utf-8")
    (context.repository_root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    context = _refreshed_context(context.repository_root)
    monkeypatch.setenv("INHERITED_SECRET", "never-write-this-trivy-secret-1234567890")
    tool = _fake_tool(
        tmp_path / "fake-trivy",
        """
import json
import os
import sys
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('Version: 0.74.0')
    raise SystemExit(0)
report_path = Path(args[args.index('--output') + 1])
stage_root = Path(args[-1])
raw = 'never' + '-write-this-trivy-secret-1234567890'
Path(__file__).with_name('captured-trivy.json').write_text(json.dumps({
    'args': args,
    'cwd': Path.cwd().as_posix(),
    'stage_files': sorted(path.relative_to(stage_root).as_posix() for path in stage_root.rglob('*') if path.is_file()),
    'dockerfile': (stage_root / 'Dockerfile').read_text(encoding='utf-8'),
    'environment_has_secret': 'INHERITED_SECRET' in os.environ,
}), encoding='utf-8')
report_path.write_text(json.dumps({
    'SchemaVersion': 2,
    'Results': [
        {
            'Target': (stage_root / 'Dockerfile').as_posix(),
            'Class': 'config',
            'Type': 'dockerfile',
            'Misconfigurations': [{
                'ID': 'DS001',
                'Severity': 'HIGH',
                'Message': raw,
                'PrimaryURL': 'https://example.invalid/' + raw,
                'CauseMetadata': {'StartLine': 3, 'Resource': raw, 'Code': {'Lines': [{'Content': raw}]}},
            }],
        },
        {
            'Target': (stage_root / 'infra.tf').as_posix(),
            'Class': 'config',
            'Type': 'terraform',
            'Misconfigurations': [],
        },
    ],
}), encoding='utf-8')
raise SystemExit(0)
""",
    )

    result = TrivyConfigControl(
        ExternalToolConfig(executable=tool.as_posix(), tool_version="0.74.0")
    ).run(context)
    captured = json.loads((tmp_path / "captured-trivy.json").read_text(encoding="utf-8"))
    raw_value = "never-write-this-trivy-secret-1234567890"

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.execution.metadata["network_mode"] == "offline-fixed-arguments"
    assert result.execution.metadata["suppression_mode"] == "policy-waivers-only"
    assert result.execution.metadata["version_verified"] == "true"
    assert result.findings[0].location and result.findings[0].location.path == "Dockerfile"
    assert result.findings[0].evidence == {
        "upstream_rule_id": "DS001",
        "upstream_severity": "HIGH",
        "artifact_category": "dockerfile",
    }
    assert raw_value not in result.findings[0].message
    assert captured["environment_has_secret"] is False
    assert captured["stage_files"] == ["Dockerfile", "infra.tf"]
    assert "trivy:ignore:" not in captured["dockerfile"].lower()
    assert captured["cwd"] != context.repository_root.as_posix()
    assert captured["args"][captured["args"].index("--scanners") + 1] == "misconfig"
    assert captured["args"][captured["args"].index("--misconfig-scanners") + 1] == "dockerfile,terraform"
    for flag in (
        "--offline-scan",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--skip-vex-repo-update",
        "--tf-exclude-downloaded-modules",
    ):
        assert flag in captured["args"]
    assert {"--config", "--config-check", "--config-data", "--tf-vars", "--helm-values", "--registry-token"}.isdisjoint(captured["args"])

    from before_deploy.models import GateOutcome, PolicyDecision, ScanManifest, ScanResult, utc_now

    now = utc_now()
    scan_result = ScanResult(
        manifest=ScanManifest(
            scan_id="trivy-adapter-test",
            repository_path=context.repository_root.as_posix(),
            repository_digest="digest",
            policy_digest="policy",
            policy_name="external",
            started_at=now,
            completed_at=now,
        ),
        executions=(result.execution,),
        findings=result.findings,
        waivers=(),
        decision=PolicyDecision(outcome=GateOutcome.BLOCK, reason_codes=("test",)),
    )
    assert raw_value not in render_json(scan_result)
    assert raw_value not in render_markdown(scan_result)
    assert raw_value not in render_sarif(scan_result)


def test_trivy_config_normalizes_terraform_and_rejects_out_of_stage_targets(tmp_path):
    context = _context(tmp_path / "repository")
    (context.repository_root / "infra.tf").write_text("resource \"x\" \"y\" {}\n", encoding="utf-8")
    context = _refreshed_context(context.repository_root)
    tool = _fake_tool(
        tmp_path / "fake-trivy-terraform",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('Version: v0.74.0')
    raise SystemExit(0)
report_path = Path(args[args.index('--output') + 1])
stage_root = Path(args[-1])
report_path.write_text(json.dumps({
    'SchemaVersion': 2,
    'Results': [{
        'Target': (stage_root / 'infra.tf').as_posix(),
        'Class': 'config',
        'Type': 'terraform',
        'Misconfigurations': [{'ID': 'AVD-AWS-0001', 'Severity': 'CRITICAL', 'CauseMetadata': {'StartLine': 1}}],
    }],
}), encoding='utf-8')
raise SystemExit(0)
""",
    )

    result = TrivyConfigControl(
        ExternalToolConfig(executable=tool.as_posix(), tool_version="0.74.0")
    ).run(context)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings[0].location and result.findings[0].location.path == "infra.tf"
    assert result.findings[0].severity.value == "BLOCKER"
    assert result.findings[0].evidence["artifact_category"] == "terraform"

    escape = _fake_tool(
        tmp_path / "fake-trivy-path-escape",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('Version: 0.74.0')
    raise SystemExit(0)
Path(args[args.index('--output') + 1]).write_text(json.dumps({
    'SchemaVersion': 2,
    'Results': [{'Target': '/outside/Dockerfile', 'Class': 'config', 'Type': 'dockerfile', 'Misconfigurations': []}],
}), encoding='utf-8')
raise SystemExit(0)
""",
    )
    escaped = TrivyConfigControl(
        ExternalToolConfig(executable=escape.as_posix(), tool_version="0.74.0")
    ).run(context)
    assert escaped.execution.status == ExecutionStatus.ERROR
    assert escaped.execution.metadata["error_kind"] == "INVALID_REPORT"


def test_trivy_config_is_not_applicable_without_artifacts_and_fails_closed_when_missing(tmp_path):
    context = _context(tmp_path / "repository")

    not_applicable = TrivyConfigControl(
        ExternalToolConfig(executable="before-deploy-missing-trivy-binary", tool_version="0.74.0")
    ).run(context)
    assert not_applicable.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert not_applicable.findings == ()

    (context.repository_root / "Containerfile").write_text("FROM scratch\n", encoding="utf-8")
    configured = _refreshed_context(context.repository_root)
    missing = TrivyConfigControl(
        ExternalToolConfig(executable="before-deploy-missing-trivy-binary", tool_version="0.74.0")
    ).run(configured)
    assert missing.execution.status == ExecutionStatus.ERROR
    assert missing.execution.metadata["error_kind"] == "EXECUTABLE_NOT_FOUND"


def test_trivy_config_fails_closed_for_version_mismatch_malformed_report_and_timeout(tmp_path):
    context = _context(tmp_path / "repository")
    (context.repository_root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    context = _refreshed_context(context.repository_root)
    mismatch = _fake_tool(
        tmp_path / "fake-trivy-version-mismatch",
        """
import sys
if sys.argv[1:] == ['--version']:
    print('Version: 0.73.0')
raise SystemExit(0)
""",
    )
    mismatch_result = TrivyConfigControl(
        ExternalToolConfig(executable=mismatch.as_posix(), tool_version="0.74.0")
    ).run(context)
    assert mismatch_result.execution.status == ExecutionStatus.ERROR
    assert mismatch_result.execution.metadata["error_kind"] == "VERSION_MISMATCH"

    malformed = _fake_tool(
        tmp_path / "fake-trivy-malformed",
        """
import sys
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('Version: 0.74.0')
    raise SystemExit(0)
Path(args[args.index('--output') + 1]).write_text('{not json', encoding='utf-8')
raise SystemExit(0)
""",
    )
    malformed_result = TrivyConfigControl(
        ExternalToolConfig(executable=malformed.as_posix(), tool_version="0.74.0")
    ).run(context)
    assert malformed_result.execution.status == ExecutionStatus.ERROR
    assert malformed_result.execution.metadata["error_kind"] == "INVALID_REPORT"

    timeout = _fake_tool(
        tmp_path / "fake-trivy-timeout",
        """
import sys
import time
if sys.argv[1:] == ['--version']:
    print('Version: 0.74.0')
    raise SystemExit(0)
time.sleep(2)
""",
    )
    timeout_result = TrivyConfigControl(
        ExternalToolConfig(executable=timeout.as_posix(), tool_version="0.74.0", timeout_seconds=1)
    ).run(context)
    assert timeout_result.execution.status == ExecutionStatus.ERROR
    assert timeout_result.execution.metadata["error_kind"] == "TIMEOUT"


def test_trivy_config_fails_closed_for_oversized_report_and_source_path_escape(tmp_path):
    context = _context(tmp_path / "repository")
    (context.repository_root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    context = _refreshed_context(context.repository_root)
    oversized = _fake_tool(
        tmp_path / "fake-trivy-oversized",
        """
import sys
from pathlib import Path
args = sys.argv[1:]
if args == ['--version']:
    print('Version: 0.74.0')
    raise SystemExit(0)
Path(args[args.index('--output') + 1]).write_bytes(b'x' * 256)
raise SystemExit(0)
""",
    )
    oversized_result = TrivyConfigControl(
        ExternalToolConfig(
            executable=oversized.as_posix(), tool_version="0.74.0", max_report_bytes=32
        )
    ).run(context)
    assert oversized_result.execution.status == ExecutionStatus.ERROR
    assert oversized_result.execution.metadata["error_kind"] == "INVALID_REPORT"

    escaped_source = tmp_path / "outside.tf"
    escaped_source.write_text("resource \"x\" \"y\" {}\n", encoding="utf-8")
    (context.repository_root / "escaped.tf").symlink_to(escaped_source)
    escaped_context = _refreshed_context(context.repository_root)
    escaped_result = TrivyConfigControl(
        ExternalToolConfig(executable=oversized.as_posix(), tool_version="0.74.0")
    ).run(escaped_context)
    assert escaped_result.execution.status == ExecutionStatus.ERROR
    assert escaped_result.execution.metadata["error_kind"] == "SOURCE_PATH_ESCAPES_REPOSITORY"


def test_cli_constructs_trivy_only_for_explicitly_configured_policy(tmp_path):
    import pytest

    from before_deploy.cli import _controls_for_profile
    from before_deploy.orchestrator import configured_controls
    from before_deploy.policy import load_policy

    repository = Path(__file__).parents[2]
    policy_path = repository / "rules" / "trivy-config-policy.yaml"
    profile = load_policy(policy_path)

    controls = configured_controls(profile, _controls_for_profile(profile, policy_path))

    assert [control.control_id for control in controls] == ["SEC-TRIVY-CONFIG-001"]
    missing_config_policy = tmp_path / "missing-trivy-config.yaml"
    missing_config_policy.write_text(
        """schema_version: 1
profile: missing-trivy-config
controls:
  SEC-TRIVY-CONFIG-001:
    required: true
    disposition: BLOCK
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="external_tools.trivy"):
        _controls_for_profile(load_policy(missing_config_policy), missing_config_policy)
