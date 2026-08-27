"""Domain evaluator: determines which security domains apply based on evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

from before_deploy.capabilities.schema import CapabilityRegistry
from before_deploy.domains.schema import ControlDefinition, SecurityDomainCatalog, SecurityDomainDefinition
from before_deploy.models import CoverageStatus, EvidenceKind, EvidenceSignal, ProjectProfile


@dataclass(frozen=True)
class DomainActivation:
    """Result of evaluating one security domain's applicability."""

    domain_id: str
    domain_version: str
    title: str
    activation_status: "ActivationStatus"
    evidence_ids: tuple[str, ...]
    rationale: str
    applicable_controls: tuple[ControlDefinition, ...]
    available_capability_ids: tuple[str, ...]
    unavailable_capability_ids: tuple[str, ...]


class ActivationStatus(str, Enum):
    """Domain activation state based on evidence."""

    ACTIVATED = "ACTIVATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DECLARED_REVIEW_REQUIRED = "DECLARED_REVIEW_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"


def evaluate_domains(
    project_profile: ProjectProfile,
    evidence_signals: Sequence[EvidenceSignal],
    domain_catalog: SecurityDomainCatalog,
    capability_registry: CapabilityRegistry,
) -> tuple[DomainActivation, ...]:
    """
    Evaluate which security domains apply based on deterministic evidence.
    
    This function implements the core principle:
    - Repository evidence → Domain activation → Control selection → Capability execution
    
    Returns a stable, sorted tuple of DomainActivation records.
    """
    evidence_ids = frozenset(signal.signal_id for signal in evidence_signals)
    
    # Get all domains that apply to this profile/evidence combination
    applicable_domains = domain_catalog.domains_for_profile(project_profile, evidence_ids)
    
    activations = []
    for domain in applicable_domains:
        # Get controls mapped to this domain
        controls = domain_catalog.controls_for_domain(domain.domain_id)
        control_ids = {ctrl.control_id for ctrl in controls}
        
        # Determine which capabilities are available vs unavailable
        available_caps = []
        unavailable_caps = []
        
        for control in controls:
            try:
                cap_def = capability_registry.definition_for_implementation(
                    control.implementation_id
                )
                if cap_def and cap_def.applies_to(project_profile):
                    available_caps.append(cap_def.capability_id)
                else:
                    unavailable_caps.append(cap_def.capability_id if cap_def else control.implementation_id)
            except Exception:
                unavailable_caps.append(control.implementation_id)
        
        # Determine activation status
        activation_status, rationale = _determine_activation_status(
            domain=domain,
            evidence_ids=evidence_ids,
            has_available_capabilities=bool(available_caps),
            has_unavailable_capabilities=bool(unavailable_caps),
        )
        
        activation = DomainActivation(
            domain_id=domain.domain_id,
            domain_version=domain.version,
            title=domain.title,
            activation_status=activation_status,
            evidence_ids=tuple(sorted(evidence_ids.intersection(
                frozenset(domain.applies_when.evidence_signal_ids)
            ))),
            rationale=rationale,
            applicable_controls=controls,
            available_capability_ids=tuple(sorted(available_caps)),
            unavailable_capability_ids=tuple(sorted(unavailable_caps)),
        )
        activations.append(activation)
    
    # Also check for domains that should be DECLARED_REVIEW_REQUIRED
    # based on requirement evidence even if not in applies_when
    review_domains = _find_declared_review_domains(
        evidence_signals=evidence_signals,
        domain_catalog=domain_catalog,
        existing_activations={a.domain_id for a in activations},
    )
    activations.extend(review_domains)
    
    return tuple(sorted(activations, key=lambda x: x.domain_id))


def _determine_activation_status(
    domain: SecurityDomainDefinition,
    evidence_ids: frozenset[str],
    has_available_capabilities: bool,
    has_unavailable_capabilities: bool,
) -> tuple[ActivationStatus, str]:
    """Determine the activation status and rationale for a domain."""
    
    # Check if domain is activated by profile/evidence
    is_activated = domain.applies_when.repository_wide or \
                   bool(domain.applies_when.languages) or \
                   bool(domain.applies_when.frameworks) or \
                   bool(domain.applies_when.package_managers) or \
                   bool(domain.applies_when.evidence_signal_ids.intersection(evidence_ids))
    
    if not is_activated:
        return (
            ActivationStatus.NOT_APPLICABLE,
            f"Domain {domain.domain_id} does not match project profile or evidence",
        )
    
    # Domain is activated - now determine coverage status
    if has_available_capabilities and not has_unavailable_capabilities:
        return (
            ActivationStatus.ACTIVATED,
            f"Domain {domain.domain_id} activated with full capability coverage",
        )
    elif has_available_capabilities and has_unavailable_capabilities:
        return (
            ActivationStatus.ACTIVATED,
            f"Domain {domain.domain_id} activated with partial capability coverage",
        )
    elif not has_available_capabilities and has_unavailable_capabilities:
        return (
            ActivationStatus.UNAVAILABLE,
            f"Domain {domain.domain_id} activated but no capabilities available for this profile",
        )
    else:
        # No controls defined yet
        return (
            ActivationStatus.UNAVAILABLE,
            f"Domain {domain.domain_id} activated but no control implementations defined",
        )


def _find_declared_review_domains(
    evidence_signals: Sequence[EvidenceSignal],
    domain_catalog: SecurityDomainCatalog,
    existing_activations: set[str],
) -> list[DomainActivation]:
    """
    Find domains that should be marked as DECLARED_REVIEW_REQUIRED.
    
    This handles cases where requirements.md declares functionality
    but the domain's applies_when doesn't catch it yet.
    """
    review_activations = []
    
    # Map requirement signals to domains that should be reviewed
    requirement_signals = {
        sig.signal_id for sig in evidence_signals 
        if sig.kind == EvidenceKind.REQUIREMENT
    }
    
    # These are high-priority domains that should always be reviewed when declared
    high_priority_requirements = {
        "REQUIREMENT-AUTHENTICATION": "DOMAIN-AUTHENTICATION-001",
        "REQUIREMENT-AUTHORIZATION": "DOMAIN-AUTHORIZATION-001",
        "REQUIREMENT-PAYMENT": "DOMAIN-PAYMENT-INTEGRATION-001",
        "REQUIREMENT-FILE-UPLOAD": "DOMAIN-FILE-UPLOAD-001",
        "REQUIREMENT-PERSONAL-DATA": "DOMAIN-SENSITIVE-DATA-001",
        "REQUIREMENT-EXTERNAL-URL-FETCH": "DOMAIN-SSRF-001",
    }
    
    for req_signal, domain_id in high_priority_requirements.items():
        if req_signal in requirement_signals and domain_id not in existing_activations:
            domain_def = domain_catalog.domains.get(domain_id)
            if domain_def:
                activation = DomainActivation(
                    domain_id=domain_id,
                    domain_version=domain_def.version,
                    title=domain_def.title,
                    activation_status=ActivationStatus.DECLARED_REVIEW_REQUIRED,
                    evidence_ids=(req_signal,),
                    rationale=f"Requirement declared in evidence: {req_signal}",
                    applicable_controls=(),
                    available_capability_ids=(),
                    unavailable_capability_ids=(),
                )
                review_activations.append(activation)
    
    return review_activations

