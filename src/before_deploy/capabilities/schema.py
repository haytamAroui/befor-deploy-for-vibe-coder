"""Strict non-executable schema for approved security capabilities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from before_deploy.models import ProjectProfile

_ALLOWED_KINDS = frozenset({"ADAPTER", "CONTROL"})


@dataclass(frozen=True)
class CapabilityDefinition:
    """Reviewed metadata for one registered control or adapter implementation."""

    capability_id: str
    version: str
    implementation_id: str
    kind: str
    title: str
    languages: frozenset[str]
    frameworks: frozenset[str]
    requires_github_workflow: bool
    required_project_signals: frozenset[str]
    security_domains: tuple[str, ...]
    exclusions: tuple[str, ...]
    source_path: Path

    def applies_to(self, project_profile: ProjectProfile) -> bool:
        """Evaluate only fixed profile predicates; no source interpretation or execution occurs."""
        if self.languages and not self.languages.intersection(project_profile.languages):
            return False
        if self.frameworks and not self.frameworks.intersection(project_profile.frameworks):
            return False
        if self.requires_github_workflow and "framework:GitHub Actions" not in project_profile.signals:
            return False
        return self.required_project_signals.issubset(project_profile.signals)


@dataclass(frozen=True)
class CapabilityRegistry:
    """Validated catalog of approved non-executable capability definitions."""

    schema_version: int
    catalog_version: str
    catalog_digest: str
    capabilities: Mapping[str, CapabilityDefinition]

    def definition_for_implementation(self, implementation_id: str) -> CapabilityDefinition | None:
        """Return the single registered definition for one control/adapter implementation."""
        matches = [
            definition
            for definition in self.capabilities.values()
            if definition.implementation_id == implementation_id
        ]
        if len(matches) > 1:
            raise ValueError(f"Multiple capabilities reference implementation: {implementation_id}")
        return matches[0] if matches else None

    def capability_ids_for_domain(self, domain: str) -> tuple[str, ...]:
        """Return stable capability IDs mapped to one audited security domain."""
        return tuple(
            sorted(
                definition.capability_id
                for definition in self.capabilities.values()
                if domain in definition.security_domains
            )
        )

    def definitions_for_domain(self, domain: str) -> tuple[CapabilityDefinition, ...]:
        """Return stable approved definitions mapped to an audited security domain."""
        return tuple(
            sorted(
                (
                    definition
                    for definition in self.capabilities.values()
                    if domain in definition.security_domains
                ),
                key=lambda item: item.capability_id,
            )
        )


def validate_kind(value: str) -> str:
    """Ensure capability kind is one of the non-executable supported categories."""
    if value not in _ALLOWED_KINDS:
        supported = ", ".join(sorted(_ALLOWED_KINDS))
        raise ValueError(f"Capability kind must be one of: {supported}")
    return value
