import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "scripts" / "prepare_release_evidence.py"


def _create_repository(path: Path) -> None:
    path.mkdir()
    (path / "pyproject.toml").write_text(
        """[project]\nname = \"example-release\"\nversion = \"1.2.3\"\n""",
        encoding="utf-8",
    )
    (path / "uv.lock").write_text(
        """version = 1\n\n[[package]]\nname = \"example-lib\"\nversion = \"4.5.6\"\n""",
        encoding="utf-8",
    )
    (path / "app.py").write_text("print('release')\n", encoding="utf-8")
    for command in (
        ("git", "init", path.as_posix()),
        ("git", "-C", path.as_posix(), "config", "user.email", "test@example.invalid"),
        ("git", "-C", path.as_posix(), "config", "user.name", "Release Test"),
        ("git", "-C", path.as_posix(), "add", "."),
        ("git", "-C", path.as_posix(), "commit", "-m", "fixture"),
    ):
        subprocess.run(command, check=True, capture_output=True)


def _prepare(repository: Path, output_dir: Path) -> dict[str, str]:
    completed = subprocess.run(
        [
            sys.executable,
            SCRIPT.as_posix(),
            "--repository",
            repository.as_posix(),
            "--output-dir",
            output_dir.as_posix(),
            "--source-date-epoch",
            "1700000000",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_release_evidence_generation_is_reproducible_and_cyclonedx(tmp_path):
    repository = tmp_path / "repository"
    _create_repository(repository)

    first = _prepare(repository, tmp_path / "first")
    second = _prepare(repository, tmp_path / "second")

    assert first["artifact_sha256"] == second["artifact_sha256"]
    assert Path(first["checksum"]).read_text(encoding="utf-8").startswith(first["artifact_sha256"])
    sbom = json.loads(Path(first["sbom"]).read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["metadata"]["component"]["name"] == "example-release"
    assert sbom["components"] == [
        {
            "name": "example-lib",
            "purl": "pkg:pypi/example-lib@4.5.6",
            "type": "library",
            "version": "4.5.6",
        }
    ]
