"""Deterministic repository technology profiling and control compatibility catalog."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from before_deploy.capabilities import CapabilityRegistry, load_builtin_capability_registry
from before_deploy.inventory import RepositoryInventory
from before_deploy.models import ControlExecution, ExecutionStatus, ProjectProfile, utc_now

_LANGUAGE_EXTENSIONS = {
    ".cs": "C#",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
}

_MANIFEST_LANGUAGES = {
    "Cargo.toml": "Rust",
    "Gemfile": "Ruby",
    "composer.json": "PHP",
    "go.mod": "Go",
    "package.json": "JavaScript",
    "pom.xml": "Java",
    "pyproject.toml": "Python",
}

_PACKAGE_MANAGERS = {
    "Cargo.lock": "cargo",
    "Gemfile.lock": "bundler",
    "go.sum": "go",
    "composer.lock": "composer",
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "yarn.lock": "yarn",
}

_FRAMEWORK_MARKERS = {
    "ASP.NET Core": ("Microsoft.AspNetCore",),
    "Django": ("django",),
    "Express": ("express",),
    "FastAPI": ("fastapi",),
    "Flask": ("flask",),
    "Laravel": ("laravel",),
    "NestJS": ("@nestjs/",),
    "Next.js": ("next",),
    "Rails": ("rails",),
    "Spring": ("spring-boot", "org.springframework"),
}


def detect_project_profile(inventory: RepositoryInventory) -> ProjectProfile:
    """Classify bounded repository evidence using only extensions, manifests, and fixed markers."""
    root_files = {path.relative_to(inventory.root).as_posix(): path for path in inventory.files}
    languages: set[str] = set()
    frameworks: set[str] = set()
    package_managers: set[str] = set()
    signals: dict[str, str] = {}

    extension_counts: dict[str, int] = {}
    for path in inventory.files:
        suffix = path.suffix.lower()
        language = _LANGUAGE_EXTENSIONS.get(suffix)
        if language:
            languages.add(language)
            extension_counts[suffix] = extension_counts.get(suffix, 0) + 1
    for extension, count in sorted(extension_counts.items()):
        signals[f"extension:{extension}"] = str(count)

    root_names = {Path(path).name for path in root_files}
    for name, language in _MANIFEST_LANGUAGES.items():
        if name in root_names:
            languages.add(language)
            signals[f"manifest:{name}"] = "1"
    for name, manager in _PACKAGE_MANAGERS.items():
        if name in root_names:
            package_managers.add(manager)
            signals[f"lockfile:{name}"] = "1"
    if any(path.endswith(".csproj") for path in root_files):
        languages.add("C#")
        signals["manifest:*.csproj"] = "1"
    if any(Path(path).name.startswith("build.gradle") for path in root_files):
        languages.add("Java")
        signals["manifest:build.gradle*"] = "1"
    if any(
        path.startswith(".github/workflows/") and Path(path).suffix in {".yaml", ".yml"}
        for path in root_files
    ):
        signals["framework:GitHub Actions"] = "1"

    candidate_text = _bounded_marker_text(root_files)
    for framework, markers in _FRAMEWORK_MARKERS.items():
        if any(marker in candidate_text for marker in markers):
            frameworks.add(framework)
            signals[f"framework:{framework}"] = "1"
    if "Next.js" in frameworks and "TypeScript" not in languages:
        languages.add("JavaScript")

    coverage_gaps = _coverage_gaps(languages, frameworks)
    return ProjectProfile(
        languages=tuple(sorted(languages)),
        frameworks=tuple(sorted(frameworks)),
        package_managers=tuple(sorted(package_managers)),
        signals=dict(sorted(signals.items())),
        coverage_gaps=coverage_gaps,
    )


def select_compatible_controls(
    controls: Iterable[object],
    project_profile: ProjectProfile,
    *,
    registry: CapabilityRegistry | None = None,
) -> tuple[tuple[object, ...], tuple[ControlExecution, ...]]:
    """Return approved runnable controls and explicit non-applicability executions.

    A control without exactly one registered capability is a construction error, not an implicit generic
    capability. The registry remains metadata-only; it never constructs or executes a control.
    """
    active_registry = registry or load_builtin_capability_registry()
    runnable: list[object] = []
    non_applicable: list[ControlExecution] = []
    for control in controls:
        control_id = getattr(control, "control_id")
        definition = active_registry.definition_for_implementation(control_id)
        if definition is None:
            raise ValueError(f"No approved capability is registered for control: {control_id}")
        reason = _non_applicability_reason(definition, project_profile)
        if reason is None:
            runnable.append(control)
            continue
        now = utc_now()
        non_applicable.append(
            ControlExecution(
                control_id=control_id,
                control_version=getattr(control, "control_version"),
                status=ExecutionStatus.NOT_APPLICABLE,
                started_at=now,
                completed_at=now,
                applicable=False,
                message=reason,
                metadata={
                    "adaptive_profile": "deterministic",
                    "capability_id": definition.capability_id,
                    "catalog_digest": active_registry.catalog_digest,
                },
            )
        )
    return tuple(runnable), tuple(non_applicable)


def _bounded_marker_text(root_files: dict[str, Path]) -> str:
    markers: list[str] = []
    preferred = {"package.json", "pyproject.toml", "pom.xml", "composer.json", "Gemfile"}
    for relative_path, path in sorted(root_files.items()):
        if Path(relative_path).name not in preferred and path.suffix.lower() not in {".py", ".ts", ".js"}:
            continue
        try:
            markers.append(path.read_text(encoding="utf-8", errors="ignore")[:200_000].lower())
        except OSError:
            continue
    return "\n".join(markers)


def _coverage_gaps(languages: set[str], frameworks: set[str]) -> tuple[str, ...]:
    gaps: list[str] = []
    for language in sorted(
        languages - {"Go", "JavaScript", "PHP", "Python", "Ruby", "Rust", "TypeScript"}
    ):
        gaps.append(f"No language-specific controls are currently installed for {language}.")
    if "PHP" in languages and "Laravel" not in frameworks:
        gaps.append("No language-specific controls are currently installed for PHP.")
    if "Ruby" in languages and "Rails" not in frameworks:
        gaps.append("No language-specific controls are currently installed for Ruby.")
    if "Rust" in languages:
        gaps.append(
            "Rust coverage is limited to an opt-in root Cargo.lock presence check for one direct Cargo.toml "
            "non-empty dependencies table plus conventional src/main.rs binary shape; Cargo values, lock "
            "contents, integrity, vulnerabilities, workspaces, custom targets, and Rust execution are not "
            "analyzed."
        )
    if "Go" in languages:
        gaps.append(
            "Go coverage is limited to root-module checksum presence, direct tls.Config InsecureSkipVerify literals, "
            "one exact offline dependency-vulnerability snapshot, and an opt-in isolated Gosec adapter; deep "
            "framework, dataflow, live-database, and runtime analysis are not installed."
        )
    if "Rails" in frameworks:
        gaps.append(
            "Rails coverage is limited to an opt-in root Gemfile.lock presence check for one unindented "
            "literal rails gem declaration plus conventional config/application.rb application shape; Gemfile "
            "values, lock contents, integrity, vulnerabilities, libraries, dynamic declarations, and Ruby "
            "execution are not analyzed."
        )
    if "Laravel" in frameworks:
        gaps.append(
            "Laravel coverage is limited to an opt-in root composer.lock presence check for one direct "
            "laravel/framework plus artisan application shape; Composer values, lock contents, integrity, "
            "vulnerabilities, runtime configuration, and PHP execution are not analyzed."
        )
    if "Next.js" in frameworks:
        gaps.append(
            "Next.js coverage is limited to direct public-env, explicit session-cookie, static CORS, and one "
            "module-level Server Action local-guard-marker check; middleware/proxy coverage, inline actions, "
            "semantic authorization, and client/server data-boundary analysis are not installed."
        )
    elif {"JavaScript", "TypeScript"}.intersection(languages):
        gaps.append(
            "No language-specific JavaScript/TypeScript controls are installed without a detected Next.js framework."
        )
    for framework in sorted(frameworks - {"FastAPI", "Laravel", "Next.js", "Rails", "GitHub Actions"}):
        gaps.append(f"{framework} is detected, but no framework-specific controls are currently installed.")
    if not languages:
        gaps.append("No supported language signal was detected; only generic controls can provide coverage.")
    return tuple(gaps)


def _non_applicability_reason(definition, project_profile: ProjectProfile) -> str | None:
    if definition.languages and not definition.languages.intersection(project_profile.languages):
        supported = ", ".join(sorted(definition.languages))
        return f"Adaptive profile: this control requires one of [{supported}]."
    if definition.frameworks and not definition.frameworks.intersection(project_profile.frameworks):
        supported = ", ".join(sorted(definition.frameworks))
        return f"Adaptive profile: this control requires one of [{supported}]."
    if definition.requires_github_workflow and "framework:GitHub Actions" not in project_profile.signals:
        return "Adaptive profile: no GitHub Actions workflow was detected."
    missing_signals = sorted(definition.required_project_signals - set(project_profile.signals))
    if missing_signals:
        return "Adaptive profile: missing required project signals [" + ", ".join(missing_signals) + "]."
    return None
