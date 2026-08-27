"""Bounded, deterministic repository evidence collection without source-content reporting."""

from __future__ import annotations

from pathlib import Path

from before_deploy.inventory import RepositoryInventory
from before_deploy.models import EvidenceKind, EvidenceSignal, Location, ProjectProfile

EVIDENCE_VERSION = "0.1.0"


def collect_repository_evidence(
    inventory: RepositoryInventory, project_profile: ProjectProfile
) -> tuple[EvidenceSignal, ...]:
    """Return stable, redaction-safe facts already established by repository inventory."""
    relative_paths = tuple(
        sorted(path.relative_to(inventory.root).as_posix() for path in inventory.files)
    )
    evidence: list[EvidenceSignal] = [
        EvidenceSignal(
            signal_id="REPOSITORY-INVENTORY",
            signal_version=EVIDENCE_VERSION,
            kind=EvidenceKind.REPOSITORY,
            title="Bounded repository inventory collected",
            location=Location(path="."),
            metadata={"scanned_file_count": str(len(relative_paths))},
        )
    ]

    for language in project_profile.languages:
        evidence.append(
            _signal(
                signal_id=f"REPOSITORY-LANGUAGE-{_identifier(language)}",
                title=f"Language detected: {language}",
                location=Location(path=_first_language_path(relative_paths, language)),
                metadata={"category": "language", "value": language},
            )
        )
    for framework in project_profile.frameworks:
        evidence.append(
            _signal(
                signal_id=f"REPOSITORY-FRAMEWORK-{_identifier(framework)}",
                title=f"Framework detected: {framework}",
                location=Location(path=_first_framework_path(relative_paths, framework)),
                metadata={"category": "framework", "value": framework},
            )
        )
    for manager in project_profile.package_managers:
        evidence.append(
            _signal(
                signal_id=f"REPOSITORY-PACKAGE-MANAGER-{_identifier(manager)}",
                title=f"Package manager evidence: {manager}",
                location=Location(path=_first_package_manager_path(relative_paths, manager)),
                metadata={"category": "package-manager", "value": manager},
            )
        )

    evidence.extend(_operational_evidence(relative_paths))
    return tuple(sorted(evidence, key=lambda item: item.signal_id))


def _operational_evidence(relative_paths: tuple[str, ...]) -> tuple[EvidenceSignal, ...]:
    definitions = (
        (
            "REPOSITORY-CI-GITHUB-ACTIONS",
            "GitHub Actions workflow detected",
            EvidenceKind.REPOSITORY,
            lambda path: path.startswith(".github/workflows/")
            and Path(path).suffix.lower() in {".yaml", ".yml"},
            "ci",
        ),
        (
            "REPOSITORY-CONTAINER-DOCKERFILE",
            "Dockerfile detected",
            EvidenceKind.INFRASTRUCTURE,
            lambda path: Path(path).name.lower().startswith("dockerfile"),
            "container",
        ),
        (
            "REPOSITORY-CONTAINER-COMPOSE",
            "Docker Compose file detected",
            EvidenceKind.INFRASTRUCTURE,
            lambda path: Path(path).name.lower()
            in {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"},
            "container",
        ),
        (
            "REPOSITORY-IAC-TERRAFORM",
            "Terraform configuration detected",
            EvidenceKind.INFRASTRUCTURE,
            lambda path: Path(path).suffix.lower() == ".tf",
            "infrastructure-as-code",
        ),
        (
            "REPOSITORY-API-OPENAPI",
            "OpenAPI document detected",
            EvidenceKind.REPOSITORY,
            lambda path: Path(path).name.lower()
            in {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"},
            "api",
        ),
    )
    evidence: list[EvidenceSignal] = []
    for signal_id, title, kind, predicate, category in definitions:
        path = next((candidate for candidate in relative_paths if predicate(candidate)), None)
        if path is None:
            continue
        evidence.append(
            EvidenceSignal(
                signal_id=signal_id,
                signal_version=EVIDENCE_VERSION,
                kind=kind,
                title=title,
                location=Location(path=path),
                metadata={"category": category},
            )
        )
    return tuple(evidence)


def _signal(
    *, signal_id: str,
    title: str,
    location: Location,
    metadata: dict[str, str],
) -> EvidenceSignal:
    return EvidenceSignal(
        signal_id=signal_id,
        signal_version=EVIDENCE_VERSION,
        kind=EvidenceKind.REPOSITORY,
        title=title,
        location=location,
        metadata=metadata,
    )


def _first_language_path(relative_paths: tuple[str, ...], language: str) -> str:
    suffixes = {
        "C#": {".cs", ".csproj"},
        "Go": {".go", ".mod"},
        "Java": {".java", ".xml", ".gradle"},
        "JavaScript": {".js", ".jsx", ".json"},
        "Kotlin": {".kt"},
        "PHP": {".php", ".json"},
        "Python": {".py", ".toml", ".txt"},
        "Ruby": {".rb"},
        "Rust": {".rs", ".toml"},
        "TypeScript": {".ts", ".tsx"},
    }.get(language, set())
    return _first_with_suffix(relative_paths, suffixes)


def _first_framework_path(relative_paths: tuple[str, ...], framework: str) -> str:
    preferred = {
        "GitHub Actions": {".github/workflows"},
        "Next.js": {"package.json", "next.config.js", "next.config.mjs", "next.config.ts"},
    }.get(framework, set())
    for path in relative_paths:
        if Path(path).name in preferred or any(path.startswith(item) for item in preferred):
            return path
    return _first_with_suffix(relative_paths, {".py", ".ts", ".js", ".json", ".xml"})


def _first_package_manager_path(relative_paths: tuple[str, ...], manager: str) -> str:
    names = {
        "bundler": "Gemfile.lock",
        "cargo": "Cargo.lock",
        "composer": "composer.lock",
        "npm": "package-lock.json",
        "pnpm": "pnpm-lock.yaml",
        "poetry": "poetry.lock",
        "uv": "uv.lock",
        "yarn": "yarn.lock",
    }
    name = names.get(manager)
    if name and name in relative_paths:
        return name
    return relative_paths[0] if relative_paths else "."


def _first_with_suffix(relative_paths: tuple[str, ...], suffixes: set[str]) -> str:
    for path in relative_paths:
        candidate = Path(path)
        if candidate.suffix.lower() in suffixes or candidate.name in suffixes:
            return path
    return relative_paths[0] if relative_paths else "."


def _identifier(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.upper()).strip("-")
