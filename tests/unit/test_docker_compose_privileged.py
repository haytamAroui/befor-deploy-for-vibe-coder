from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.docker_compose import DockerComposePrivilegedControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path):
    inventory = collect_inventory(tmp_path)
    return DockerComposePrivilegedControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def test_compose_privileged_control_reports_direct_literal_true_only(tmp_path: Path):
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  web:\n"
        "    image: example:latest\n"
        "    privileged: true\n"
        "    source_only_note: do-not-report-compose-value\n",
        encoding="utf-8",
    )

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.location is not None
    assert finding.location.path == "compose.yaml"
    assert finding.location.start_line == 4
    assert finding.evidence == {"artifact": "compose", "issue": "privileged_service"}
    assert "web" not in finding.message
    assert "example:latest" not in finding.message
    assert "do-not-report-compose-value" not in finding.message


def test_compose_privileged_control_accepts_direct_false(tmp_path: Path):
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    privileged: false\n", encoding="utf-8"
    )

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert not result.findings


def test_compose_privileged_control_excludes_dynamic_or_reused_forms(tmp_path: Path):
    cases = (
        "services:\n  web:\n    privileged: \"true\"\n",
        "services:\n  web:\n    privileged: True\n",
        "services:\n  web:\n    privileged: ${PRIVILEGED}\n",
        "services:\n  defaults: &defaults\n    privileged: true\n  web:\n    <<: *defaults\n",
        "include:\n  - nested.compose.yml\nservices:\n  web:\n    privileged: true\n",
        "services:\n  web:\n    profiles: [dev]\n    privileged: true\n",
    )

    for index, source in enumerate(cases):
        case_directory = tmp_path / str(index)
        case_directory.mkdir()
        (case_directory / "docker-compose.yaml").write_text(source, encoding="utf-8")

        result = _run(case_directory)

        assert result.execution.status == ExecutionStatus.COMPLETED
        assert not result.findings


def test_compose_privileged_control_normalizes_invalid_yaml(tmp_path: Path):
    (tmp_path / "compose.yaml").write_text("services: [\n", encoding="utf-8")

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata == {"error_kind": "COMPOSE_YAML_INVALID"}
    assert "services" not in result.execution.message


def test_compose_privileged_control_normalizes_unreadable_file(tmp_path: Path, monkeypatch):
    compose_path = tmp_path / "compose.yaml"
    compose_path.write_text("services: {}\n", encoding="utf-8")

    original_read_text = Path.read_text

    def _unreadable(self, *args, **kwargs):
        if self == compose_path:
            raise OSError("source-only compose read error")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _unreadable)
    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata == {"error_kind": "COMPOSE_YAML_UNREADABLE"}
    assert "source-only compose read error" not in result.execution.message


def test_compose_privileged_control_normalizes_invalid_encoding(tmp_path: Path):
    (tmp_path / "compose.yaml").write_bytes(b"\xffsource_only_invalid_encoding")

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata == {"error_kind": "COMPOSE_YAML_INVALID_ENCODING"}
    assert "source_only_invalid_encoding" not in result.execution.message
