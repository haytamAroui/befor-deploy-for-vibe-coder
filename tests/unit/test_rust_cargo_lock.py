from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.rust_cargo import RustCargoLockfileControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path):
    inventory = collect_inventory(tmp_path)
    return RustCargoLockfileControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def _write_conventional_binary(tmp_path: Path, cargo_toml: str) -> None:
    (tmp_path / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")
    source_directory = tmp_path / "src"
    source_directory.mkdir()
    (source_directory / "main.rs").write_text("fn main() {}\n", encoding="utf-8")


def test_rust_cargo_lock_control_reports_only_a_missing_root_lockfile(tmp_path: Path):
    _write_conventional_binary(
        tmp_path,
        '[package]\nname = "fixture"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1"\n',
    )

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.location is not None
    assert finding.location.path == "Cargo.toml"
    assert finding.location.start_line == 1
    assert finding.evidence == {
        "ecosystem": "cargo",
        "target": "conventional_binary",
        "issue": "cargo_lock_missing",
    }
    assert "tokio" not in finding.message
    assert '"1"' not in finding.message


def test_rust_cargo_lock_control_accepts_only_root_lockfile_presence(tmp_path: Path):
    _write_conventional_binary(
        tmp_path,
        '[package]\nname = "fixture"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1"\n',
    )
    (tmp_path / "Cargo.lock").write_text("not parsed by this control\n", encoding="utf-8")

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert not result.findings


def test_rust_cargo_lock_control_excludes_libraries_and_empty_dependency_tables(tmp_path: Path):
    library_directory = tmp_path / "library"
    library_directory.mkdir()
    (library_directory / "Cargo.toml").write_text(
        '[dependencies]\ntokio = "1"\n', encoding="utf-8"
    )
    library_source = library_directory / "src"
    library_source.mkdir()
    (library_source / "lib.rs").write_text("pub fn library() {}\n", encoding="utf-8")

    empty_dependencies_directory = tmp_path / "empty"
    empty_dependencies_directory.mkdir()
    _write_conventional_binary(empty_dependencies_directory, "[dependencies]\n")

    for directory in (library_directory, empty_dependencies_directory):
        result = _run(directory)

        assert result.execution.status in {
            ExecutionStatus.COMPLETED,
            ExecutionStatus.NOT_APPLICABLE,
        }
        assert not result.findings


def test_rust_cargo_lock_control_normalizes_malformed_manifest_error(tmp_path: Path):
    _write_conventional_binary(tmp_path, '[dependencies\nsource_only_invalid = "value"\n')

    result = _run(tmp_path)

    assert result.execution.status == ExecutionStatus.ERROR
    assert result.execution.metadata == {"error_kind": "CARGO_MANIFEST_INVALID"}
    assert "source_only_invalid" not in result.execution.message
