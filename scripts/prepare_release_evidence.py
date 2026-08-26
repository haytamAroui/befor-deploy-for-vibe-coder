#!/usr/bin/env python3
"""Create reproducible source-release evidence without executing project code."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import tarfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path


@dataclass(frozen=True)
class ProjectMetadata:
    name: str
    version: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a reproducible source artifact, checksum, and CycloneDX SBOM."
    )
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=_source_date_epoch(),
        help="Unix timestamp embedded in the deterministic archive (default: SOURCE_DATE_EPOCH or 0).",
    )
    args = parser.parse_args(argv)
    if args.source_date_epoch < 0:
        parser.error("--source-date-epoch must be non-negative")

    repository = args.repository.resolve()
    metadata = _read_project_metadata(repository)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = output_dir / f"{metadata.name}-{metadata.version}.tar.gz"
    sbom = output_dir / f"{metadata.name}-{metadata.version}.cdx.json"
    checksum = output_dir / f"{metadata.name}-{metadata.version}.sha256"

    _write_reproducible_archive(repository, artifact, metadata, args.source_date_epoch)
    digest = _sha256_file(artifact)
    checksum.write_text(f"{digest}  {artifact.name}\n", encoding="utf-8")
    _write_cyclonedx_sbom(repository, sbom, metadata)
    summary = {
        "artifact": artifact.as_posix(),
        "artifact_sha256": digest,
        "sbom": sbom.as_posix(),
        "checksum": checksum.as_posix(),
        "source_date_epoch": args.source_date_epoch,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def _source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        return int(raw)
    except ValueError as error:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from error


def _read_project_metadata(repository: Path) -> ProjectMetadata:
    pyproject = repository / "pyproject.toml"
    try:
        document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = document["project"]
        name = project["name"]
        version = project["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise ValueError("pyproject.toml must contain project.name and project.version") from error
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ValueError("project.name and project.version must be non-empty strings")
    return ProjectMetadata(name=name, version=version)


def _tracked_files(repository: Path) -> tuple[Path, ...]:
    try:
        completed = subprocess.run(
            ["git", "-C", repository.as_posix(), "ls-files", "-z"],
            check=True,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ValueError("Release preparation requires a readable Git working tree") from error
    paths: list[Path] = []
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(raw_path.decode("utf-8"))
        candidate = repository / relative
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"Tracked release entry must be a regular file: {relative.as_posix()}")
        paths.append(relative)
    if not paths:
        raise ValueError("Release preparation found no tracked files")
    return tuple(sorted(paths, key=lambda path: path.as_posix()))


def _write_reproducible_archive(
    repository: Path, artifact: Path, metadata: ProjectMetadata, source_date_epoch: int
) -> None:
    prefix = f"{metadata.name}-{metadata.version}"
    archive_bytes = BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for relative_path in _tracked_files(repository):
            data = (repository / relative_path).read_bytes()
            entry = tarfile.TarInfo(name=f"{prefix}/{relative_path.as_posix()}")
            entry.size = len(data)
            entry.mtime = source_date_epoch
            entry.uid = 0
            entry.gid = 0
            entry.uname = ""
            entry.gname = ""
            entry.mode = 0o755 if relative_path.parts[0] == "scripts" else 0o644
            tar.addfile(entry, BytesIO(data))
    with artifact.open("wb") as raw_file:
        with gzip.GzipFile(fileobj=raw_file, mode="wb", mtime=source_date_epoch, filename="") as compressed:
            compressed.write(archive_bytes.getvalue())


def _write_cyclonedx_sbom(repository: Path, output_path: Path, metadata: ProjectMetadata) -> None:
    components = _uv_lock_components(repository / "uv.lock")
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:sha256-{_sha256_file(repository / 'uv.lock')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.fromtimestamp(_source_date_epoch(), tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "component": {
                "type": "application",
                "name": metadata.name,
                "version": metadata.version,
            },
        },
        "components": components,
    }
    output_path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _uv_lock_components(lock_path: Path) -> list[dict[str, str]]:
    try:
        document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        packages = document["package"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise ValueError("A valid uv.lock file is required to generate release SBOM evidence") from error
    if not isinstance(packages, list):
        raise ValueError("uv.lock package entries must be a list")
    components: list[dict[str, str]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("uv.lock package entry must be a mapping")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ValueError("uv.lock package entries require non-empty name and version")
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}",
            }
        )
    return sorted(components, key=lambda component: (component["name"], component["version"]))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
