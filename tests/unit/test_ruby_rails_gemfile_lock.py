from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.ruby_rails import RailsGemfileLockfileControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path):
    inventory = collect_inventory(tmp_path)
    return RailsGemfileLockfileControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def _write_rails_shape(tmp_path: Path, gemfile: str) -> None:
    (tmp_path / "Gemfile").write_text(gemfile, encoding="utf-8")
    config_directory = tmp_path / "config"
    config_directory.mkdir()
    (config_directory / "application.rb").write_text("module Fixture\nend\n", encoding="utf-8")


def test_rails_gemfile_lock_control_reports_only_a_missing_root_lockfile(tmp_path: Path):
    _write_rails_shape(
        tmp_path,
        'gem "rails", "8.1"\nsource_only_note = "do-not-report-gemfile-value"\n',
    )

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.location is not None
    assert finding.location.path == "Gemfile"
    assert finding.location.start_line == 1
    assert finding.evidence == {
        "ecosystem": "bundler",
        "framework": "rails",
        "issue": "gemfile_lock_missing",
    }
    assert "8.1" not in finding.message
    assert "do-not-report-gemfile-value" not in finding.message


def test_rails_gemfile_lock_control_accepts_only_root_lockfile_presence(tmp_path: Path):
    _write_rails_shape(tmp_path, "gem 'rails', '8.1'\n")
    (tmp_path / "Gemfile.lock").write_text("not parsed by this control\n", encoding="utf-8")

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert not result.findings


def test_rails_gemfile_lock_control_excludes_indented_and_parenthesized_declarations(
    tmp_path: Path,
):
    cases = (
        "group :development do\n  gem 'rails', '8.1'\nend\n",
        "gem('rails', '8.1')\n",
    )

    for index, gemfile in enumerate(cases):
        case_directory = tmp_path / str(index)
        case_directory.mkdir()
        _write_rails_shape(case_directory, gemfile)

        result = _run(case_directory)

        assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
        assert not result.findings


def test_rails_gemfile_lock_control_normalizes_unreadable_gemfile_error(
    tmp_path: Path, monkeypatch
):
    _write_rails_shape(tmp_path, "gem 'rails', '8.1'\n")

    def _unreadable(self, *args, **kwargs):
        del self, args, kwargs
        raise OSError("source-only read error")

    monkeypatch.setattr(Path, "read_text", _unreadable)
    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata == {"error_kind": "GEMFILE_UNREADABLE"}
    assert "source-only read error" not in result.execution.message
