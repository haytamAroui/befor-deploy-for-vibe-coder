import json
from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.external import ExternalToolConfig
from before_deploy.controls.gitleaks import GitleaksControl
from before_deploy.controls.semgrep import SemgrepControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus
from before_deploy.reports import render_json, render_markdown, render_sarif


def _context(repository: Path) -> ControlContext:
    repository.mkdir()
    (repository / "app.py").write_text("print('safe')\n", encoding="utf-8")
    inventory = collect_inventory(repository)
    return ControlContext(repository_root=repository, inventory=inventory)


def _fake_tool(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | 0o111)
    return path


def test_gitleaks_adapter_normalizes_and_redacts_raw_secret(tmp_path):
    context = _context(tmp_path / "repository")
    tool = _fake_tool(
        tmp_path / "fake-gitleaks",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
report_path = Path(args[args.index('--report-path') + 1])
record = {
    'RuleID': 'fixture-rule',
    'File': 'app.py',
    'StartLine': 1,
    'Fingerprint': 'fixture-upstream-fingerprint',
}
record['Sec' + 'ret'] = 'never' + '-write-this-to-a-report-1234567890'
record['Match'] = 'api_key = ' + record['Sec' + 'ret']
report_path.write_text(json.dumps([record]), encoding='utf-8')
raise SystemExit(1)
""",
    )

    result = GitleaksControl(ExternalToolConfig(executable=tool.as_posix())).run(context)
    raw_value = "never" + "-write-this-to-a-report-1234567890"

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.location and finding.location.path == "app.py"
    assert raw_value not in finding.message

    from before_deploy.models import GateOutcome, PolicyDecision, ScanManifest, ScanResult, utc_now

    now = utc_now()
    scan_result = ScanResult(
        manifest=ScanManifest(
            scan_id="adapter-test",
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


def test_semgrep_adapter_uses_local_rules_and_privacy_flags(tmp_path):
    context = _context(tmp_path / "repository")
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()
    (rule_directory / "rule.yaml").write_text("rules: []\n", encoding="utf-8")
    tool = _fake_tool(
        tmp_path / "fake-semgrep",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
Path('captured-semgrep-args.json').write_text(json.dumps(args), encoding='utf-8')
report_path = Path(args[args.index('--json-output') + 1])
report = {
    'results': [{
        'check_id': 'before-deploy.python.sql-string-interpolation',
        'path': 'app.py',
        'start': {'line': 1},
        'extra': {'severity': 'ERROR'},
    }],
    'errors': [],
}
report_path.write_text(json.dumps(report), encoding='utf-8')
raise SystemExit(0)
""",
    )

    result = SemgrepControl(
        ExternalToolConfig(executable=tool.as_posix()), rule_directory=rule_directory
    ).run(context)
    arguments = (context.repository_root / "captured-semgrep-args.json").read_text(encoding="utf-8")

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings[0].rule_id == "SEC-SAST-SEMGREP-001"
    assert "--metrics=off" in arguments
    assert "--no-autofix" in arguments
    assert "--allow-local-builds" not in arguments


def test_missing_external_binary_is_an_explicit_error(tmp_path):
    context = _context(tmp_path / "repository")

    result = GitleaksControl(
        ExternalToolConfig(executable="before-deploy-missing-gitleaks-binary")
    ).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "EXECUTABLE_NOT_FOUND"


def test_semgrep_reported_errors_are_not_treated_as_a_clean_scan(tmp_path):
    context = _context(tmp_path / "repository")
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()
    tool = _fake_tool(
        tmp_path / "fake-semgrep-error",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
report_path = Path(args[args.index('--json-output') + 1])
report_path.write_text(json.dumps({'results': [], 'errors': [{'type': 'ParseError'}]}), encoding='utf-8')
raise SystemExit(0)
""",
    )

    result = SemgrepControl(
        ExternalToolConfig(executable=tool.as_posix()), rule_directory=rule_directory
    ).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "SCANNER_REPORTED_ERRORS"


def test_external_tool_timeout_is_an_explicit_error(tmp_path):
    context = _context(tmp_path / "repository")
    tool = _fake_tool(
        tmp_path / "fake-gitleaks-timeout",
        """
import time
time.sleep(2)
""",
    )

    result = GitleaksControl(
        ExternalToolConfig(executable=tool.as_posix(), timeout_seconds=1)
    ).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "TIMEOUT"


def test_gosec_adapter_uses_fixed_offline_arguments_and_redacts_upstream_source(tmp_path):
    from before_deploy.controls.gosec import GosecControl

    context = _context(tmp_path / "repository")
    tool = _fake_tool(
        tmp_path / "fake-gosec",
        """
import json
import os
import sys
from pathlib import Path
args = sys.argv[1:]
Path('captured-gosec.json').write_text(json.dumps({
    'args': args,
    'environment': {key: os.environ.get(key) for key in ('GOFLAGS', 'GOPROXY', 'GOSUMDB', 'GONOSUMDB', 'GIT_TERMINAL_PROMPT')},
}), encoding='utf-8')
report_path = Path(args[args.index('-out') + 1])
raw = 'never' + '-write-this-gosec-source-1234567890'
report_path.write_text(json.dumps({
    'Golang errors': '',
    'Issues': [{
        'rule_id': 'G204',
        'severity': 'HIGH',
        'confidence': 'HIGH',
        'file': 'app.py',
        'line': '1',
        'cwe': {'id': '78'},
        'details': raw,
        'code': 'exec(' + raw + ')',
    }],
}), encoding='utf-8')
raise SystemExit(0)
""",
    )

    result = GosecControl(ExternalToolConfig(executable=tool.as_posix(), tool_version="v2.29.0")).run(
        context
    )
    captured = json.loads((context.repository_root / "captured-gosec.json").read_text(encoding="utf-8"))
    raw_value = "never" + "-write-this-gosec-source-1234567890"

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings[0].location and result.findings[0].location.path == "app.py"
    assert result.findings[0].evidence == {
        "upstream_rule_id": "G204",
        "upstream_severity": "HIGH",
        "upstream_confidence": "HIGH",
        "upstream_cwe_id": "78",
    }
    assert raw_value not in result.findings[0].message
    assert "-fmt=json" in captured["args"]
    assert "-no-fail" in captured["args"]
    assert "-exclude-generated" in captured["args"]
    assert "-nosec=true" in captured["args"]
    assert "-nosec-require-rules" in captured["args"]
    assert "-nosec-require-justification" in captured["args"]
    assert "./..." in captured["args"]
    assert {
        "-ai-api-provider",
        "-ai-api-key",
        "-ai-base-url",
        "-ai-skip-ssl",
    }.isdisjoint(captured["args"])
    assert captured["environment"] == {
        "GOFLAGS": "-mod=readonly",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GONOSUMDB": "*",
        "GIT_TERMINAL_PROMPT": "0",
    }

    from before_deploy.models import GateOutcome, PolicyDecision, ScanManifest, ScanResult, utc_now

    now = utc_now()
    scan_result = ScanResult(
        manifest=ScanManifest(
            scan_id="gosec-adapter-test",
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


def test_gosec_reported_errors_are_not_treated_as_a_clean_scan(tmp_path):
    from before_deploy.controls.gosec import GosecControl

    context = _context(tmp_path / "repository")
    tool = _fake_tool(
        tmp_path / "fake-gosec-error",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
report_path = Path(args[args.index('-out') + 1])
report_path.write_text(json.dumps({'Golang errors': {'error': 'compile failed'}, 'Issues': []}), encoding='utf-8')
raise SystemExit(0)
""",
    )

    result = GosecControl(ExternalToolConfig(executable=tool.as_posix())).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "SCANNER_REPORTED_ERRORS"


def test_external_runner_rejects_unapproved_environment_override(tmp_path):
    from before_deploy.controls.external import ExternalToolRunner

    context = _context(tmp_path / "repository")
    tool = _fake_tool(tmp_path / "fake-tool", "raise SystemExit(0)\n")

    outcome = ExternalToolRunner().run(
        config=ExternalToolConfig(executable=tool.as_posix()),
        arguments=(),
        cwd=context.repository_root,
        environment_overrides={"UNAPPROVED_OVERRIDE": "value"},
    )

    assert outcome.error_kind == "INVALID_ENVIRONMENT_OVERRIDE"
