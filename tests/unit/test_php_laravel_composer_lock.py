from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.php_laravel import LaravelComposerLockfileControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path):
    inventory = collect_inventory(tmp_path)
    return LaravelComposerLockfileControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def _write_laravel_shape(tmp_path: Path, composer_json: str) -> None:
    (tmp_path / "composer.json").write_text(composer_json, encoding="utf-8")
    (tmp_path / "artisan").write_text("<?php\n", encoding="utf-8")
    (tmp_path / "app.php").write_text("<?php\n", encoding="utf-8")


def test_laravel_composer_lock_control_reports_only_a_missing_root_lockfile(tmp_path: Path):
    _write_laravel_shape(
        tmp_path,
        '{"require": {"laravel/framework": "^12.0"}, "extra": "source-only-value"}',
    )

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.location is not None
    assert finding.location.path == "composer.json"
    assert finding.location.start_line == 1
    assert finding.evidence == {
        "ecosystem": "composer",
        "framework": "laravel",
        "issue": "composer_lock_missing",
    }
    assert "^12.0" not in finding.message
    assert "source-only-value" not in finding.message


def test_laravel_composer_lock_control_accepts_only_root_lockfile_presence(tmp_path: Path):
    _write_laravel_shape(tmp_path, '{"require": {"laravel/framework": "^12.0"}}')
    (tmp_path / "composer.lock").write_text("not parsed by this control", encoding="utf-8")

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert not result.findings


def test_laravel_composer_lock_control_does_not_infer_incomplete_or_non_laravel_shapes(
    tmp_path: Path,
):
    cases = (
        ('{"require": {"laravel/framework": "^12.0"}}', False),
        ('{"require": {"vendor/other": "^1.0"}}', True),
        ('{"require-dev": {"laravel/framework": "^12.0"}}', True),
    )

    for index, (composer_json, with_artisan) in enumerate(cases):
        case_directory = tmp_path / str(index)
        case_directory.mkdir()
        (case_directory / "composer.json").write_text(composer_json, encoding="utf-8")
        if with_artisan:
            (case_directory / "artisan").write_text("<?php\n", encoding="utf-8")

        result = _run(case_directory)

        assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
        assert not result.findings


def test_laravel_composer_lock_control_normalizes_malformed_manifest_error(tmp_path: Path):
    _write_laravel_shape(tmp_path, '{"require": {"laravel/framework": "unterminated}')

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata == {"error_kind": "COMPOSER_MANIFEST_INVALID"}
    assert "unterminated" not in result.execution.message
