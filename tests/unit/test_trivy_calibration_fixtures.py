from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.external import ExternalToolConfig
from before_deploy.controls.trivy_config import (
    TrivyConfigControl,
    _eligible_source_paths,
    _stage_sources,
)
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "trivy_config_calibration"


def _context(name: str) -> ControlContext:
    root = FIXTURE_ROOT / name
    return ControlContext(repository_root=root.resolve(), inventory=collect_inventory(root))


def test_calibration_fixture_matrix_has_the_declared_static_scope():
    assert {path.name for path in _eligible_source_paths(_context("secure"))} == {"Dockerfile", "main.tf"}
    assert {path.name for path in _eligible_source_paths(_context("vulnerable"))} == {
        "Dockerfile",
        "main.tf",
    }
    assert {path.name for path in _eligible_source_paths(_context("ambiguous"))} == {"main.tf"}
    assert {path.name for path in _eligible_source_paths(_context("suppression"))} == {"main.tf"}
    assert _eligible_source_paths(_context("unsupported")) == ()


def test_unsupported_calibration_fixture_does_not_start_a_missing_trivy_binary():
    result = TrivyConfigControl(
        ExternalToolConfig(executable="before-deploy-missing-trivy-binary", tool_version="0.74.0")
    ).run(_context("unsupported"))

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_suppression_fixture_is_staged_without_target_ignore_file_or_inline_directive(tmp_path):
    context = _context("suppression")
    staged = _stage_sources(
        repository_root=context.repository_root,
        source_paths=_eligible_source_paths(context),
        stage_root=tmp_path / "stage",
    )

    assert set(staged) == {Path("main.tf")}
    staged_content = (tmp_path / "stage" / "main.tf").read_text(encoding="utf-8").lower()
    assert "trivy:ignore:" not in staged_content
    assert not (tmp_path / "stage" / ".trivyignore").exists()
