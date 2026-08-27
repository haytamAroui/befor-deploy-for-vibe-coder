"""Immutable, non-executable models for the security-domain and control catalog."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from before_deploy.models import ProjectProfile

_ALLOWED_CATEGORIES = frozenset(
    {
        "APPLICATION_SECURITY",
        "ASSURANCE",
        "CONFIGURATION_SECURITY",
        "INFRASTRUCTURE_SECURITY",
        "SUPPLY_CHAIN_SECURITY",
    }
)


@dataclass(frozen=True)
class DomainApplicability:
    """Fixed profile and evidence predicates that activate a catalog domain."""

    repository_wide: bool
    languages: frozenset[str]
    frameworks: frozenset[str]
    package_managers: frozenset[str]
    evidence_signal_ids: frozenset[str]

    def applies_to(self, project_profile: ProjectProfile, evidence_ids: frozenset[str]) -> bool:
        """Evaluate metadata-only predicates without interpreting repository content."""
        return any(
            (
                self.repository_wide,
                bool(self.languages.intersection(project_profile.languages)),
                bool(self.frameworks.intersection(project_profile.frameworks)),
                bool(self.package_managers.intersection(project_profile.package_managers)),
                bool(self.evidence_signal_ids.intersection(evidence_ids)),
            )
        )


@dataclass(frozen=True)
class SecurityDomainDefinition:
    """One versioned security domain; its existence never establishes coverage or compliance."""

    domain_id: str
    version: str
    title: str
    category: str
    description: str
    applies_when: DomainApplicability
    reference_ids: tuple[str, ...]
    exclusions: tuple[str, ...]
    source_path: Path


@dataclass(frozen=True)
class ControlDefinition:
    """One reviewed detection contract mapped to an existing capability implementation."""

    control_id: str
    version: str
    title: str
    capability_id: str
    implementation_id: str
    security_domain_ids: tuple[str, ...]
    detection_scope: str
    exclusions: tuple[str, ...]
    reference_ids: tuple[str, ...]
    source_path: Path


@dataclass(frozen=True)
class SecurityDomainCatalog:
    """Validated, packaged, informational metadata for domains and existing control contracts."""

    schema_version: int
    catalog_version: str
    catalog_digest: str
    domains: Mapping[str, SecurityDomainDefinition]
    controls: Mapping[str, ControlDefinition]

    def domains_for_profile(
        self, project_profile: ProjectProfile, evidence_ids: frozenset[str]
    ) -> tuple[SecurityDomainDefinition, ...]:
        """Return stable catalog domains activated by observed deterministic profile/evidence facts."""
        return tuple(
            sorted(
                (
                    domain
                    for domain in self.domains.values()
                    if domain.applies_when.applies_to(project_profile, evidence_ids)
                ),
                key=lambda item: item.domain_id,
            )
        )

    def controls_for_domain(self, domain_id: str) -> tuple[ControlDefinition, ...]:
        """Return stable reviewed control contracts mapped to one domain."""
        return tuple(
            sorted(
                (
                    control
                    for control in self.controls.values()
                    if domain_id in control.security_domain_ids
                ),
                key=lambda item: item.control_id,
            )
        )


def validate_category(value: str) -> str:
    """Ensure catalog category is descriptive taxonomy, not an executable mode."""
    if value not in _ALLOWED_CATEGORIES:
        supported = ", ".join(sorted(_ALLOWED_CATEGORIES))
        raise ValueError(f"Security domain category must be one of: {supported}")
    return value
