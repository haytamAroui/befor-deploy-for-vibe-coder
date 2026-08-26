import json
from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.dependency_audit import DependencyAuditControl
from before_deploy.controls.external import ExternalToolConfig
from before_deploy.controls.provenance import ProvenanceControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus
from before_deploy.policy import DependencyAuditPolicy, ProvenancePolicy


def _context(repository: Path) -> ControlContext:
    repository.mkdir()
    (repository / "app.py").write_text("print('safe')\n", encoding="utf-8")
    inventory = collect_inventory(repository)
    return ControlContext(repository_root=repository, inventory=inventory)


def _fake_tool(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | 0o111)
    return path


def test_dependency_audit_normalizes_known_vulnerabilities_without_description(tmp_path):
    context = _context(tmp_path / "repository")
    (context.repository_root / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    tool = _fake_tool(
        tmp_path / "fake-pip-audit",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
report_path = Path(args[args.index('--output') + 1])
report = [{
    'name': 'example',
    'version': '1.0',
    'vulns': [{
        'id': 'CVE-2026-0001',
        'aliases': ['GHSA-example'],
        'fix_versions': ['1.1'],
        'description': 'do not retain this verbose advisory detail',
    }],
}]
report_path.write_text(json.dumps(report), encoding='utf-8')
raise SystemExit(1)
""",
    )

    result = DependencyAuditControl(
        ExternalToolConfig(executable=tool.as_posix(), tool_version="test"),
        DependencyAuditPolicy(input_kind="requirements", requirements_path="requirements.txt"),
    ).run(context)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-DEP-VULN-001"
    assert finding.evidence["package"] == "example"
    assert finding.evidence["vulnerability_id"] == "CVE-2026-0001"
    assert "verbose advisory detail" not in finding.message


def test_dependency_audit_rejects_contradictory_exit_and_report(tmp_path):
    context = _context(tmp_path / "repository")
    (context.repository_root / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    tool = _fake_tool(
        tmp_path / "fake-pip-audit-contradiction",
        """
import json
import sys
from pathlib import Path
args = sys.argv[1:]
Path(args[args.index('--output') + 1]).write_text(json.dumps([]), encoding='utf-8')
raise SystemExit(1)
""",
    )

    result = DependencyAuditControl(
        ExternalToolConfig(executable=tool.as_posix(), tool_version="test"),
        DependencyAuditPolicy(input_kind="requirements", requirements_path="requirements.txt"),
    ).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "EXIT_REPORT_CONTRADICTION"


def test_dependency_audit_requires_uv_lock_for_uv_input(tmp_path):
    context = _context(tmp_path / "repository")

    result = DependencyAuditControl(
        ExternalToolConfig(executable="not-used", tool_version="test"),
        DependencyAuditPolicy(input_kind="uv_lock"),
        uv_config=ExternalToolConfig(executable="also-not-used", tool_version="test"),
    ).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "UV_LOCK_NOT_FOUND"


def test_provenance_adapter_enforces_expected_identity_arguments(tmp_path):
    context = _context(tmp_path / "repository")
    artifact = context.repository_root / "dist" / "app.tar.gz"
    artifact.parent.mkdir()
    artifact.write_bytes(b"artifact")
    bundle = context.repository_root / "attestations" / "app.intoto.jsonl"
    bundle.parent.mkdir()
    bundle.write_text("bundle", encoding="utf-8")
    tool = _fake_tool(
        tmp_path / "fake-gh",
        """
import json
import sys
from pathlib import Path
Path('captured-gh-arguments.json').write_text(json.dumps(sys.argv[1:]), encoding='utf-8')
print(json.dumps([{
  'verificationResult': {
    'signature': {'certificate': {'subjectAlternativeName': 'workflow'}},
    'verifiedTimestamps': [{'uri': 'transparency-log'}],
  }
}]))
raise SystemExit(0)
""",
    )
    policy = ProvenancePolicy(
        artifact_path="dist/app.tar.gz",
        bundle_path="attestations/app.intoto.jsonl",
        repository="owner/repository",
        signer_workflow="owner/repository/.github/workflows/release.yml",
    )

    result = ProvenanceControl(
        ExternalToolConfig(executable=tool.as_posix(), tool_version="test"), policy
    ).run(context)
    arguments = json.loads((context.repository_root / "captured-gh-arguments.json").read_text())

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.execution.metadata["verified_attestation_count"] == "1"
    assert "--bundle" in arguments
    assert "--repo" in arguments
    assert "--signer-workflow" in arguments
    assert "https://slsa.dev/provenance/v1" in arguments
    assert "--deny-self-hosted-runners" in arguments


def test_provenance_adapter_rejects_unverified_json_shape(tmp_path):
    context = _context(tmp_path / "repository")
    artifact = context.repository_root / "app.tar.gz"
    artifact.write_bytes(b"artifact")
    bundle = context.repository_root / "app.intoto.jsonl"
    bundle.write_text("bundle", encoding="utf-8")
    tool = _fake_tool(
        tmp_path / "fake-gh-invalid",
        """
import json
print(json.dumps([{'verificationResult': {'signature': {'certificate': {}}}}]))
raise SystemExit(0)
""",
    )
    policy = ProvenancePolicy(
        artifact_path="app.tar.gz",
        bundle_path="app.intoto.jsonl",
        repository="owner/repository",
        signer_workflow="owner/repository/.github/workflows/release.yml",
    )

    result = ProvenanceControl(
        ExternalToolConfig(executable=tool.as_posix(), tool_version="test"), policy
    ).run(context)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata["error_kind"] == "VERIFIED_EVIDENCE_MISSING"
