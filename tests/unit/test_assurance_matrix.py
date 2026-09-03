from pathlib import Path

import pytest

from before_deploy.assurance import (
    build_assurance_matrix,
    render_assurance_matrix_markdown,
)
from before_deploy.capabilities import CapabilityDefinition, CapabilityRegistry
from before_deploy.domains import (
    ControlDefinition,
    DomainApplicability,
    SecurityDomainCatalog,
    SecurityDomainDefinition,
)


def _domain(domain_id: str, title: str) -> SecurityDomainDefinition:
    return SecurityDomainDefinition(
        domain_id=domain_id,
        version="1",
        title=title,
        category="APPLICATION_SECURITY",
        description="test",
        applies_when=DomainApplicability(
            repository_wide=True,
            languages=frozenset(),
            frameworks=frozenset(),
            package_managers=frozenset(),
            evidence_signal_ids=frozenset(),
        ),
        reference_ids=(),
        exclusions=(),
        source_path=Path("domains.yaml"),
    )


def _capability(
    capability_id: str,
    implementation_id: str,
    *,
    kind: str = "CONTROL",
    languages: frozenset[str] = frozenset(),
    frameworks: frozenset[str] = frozenset(),
) -> CapabilityDefinition:
    return CapabilityDefinition(
        capability_id=capability_id,
        version="1",
        implementation_id=implementation_id,
        kind=kind,
        title=capability_id,
        languages=languages,
        frameworks=frameworks,
        requires_github_workflow=False,
        required_project_signals=frozenset(),
        security_domains=(),
        exclusions=(),
        source_path=Path("capability.yaml"),
    )


def _control(
    control_id: str,
    capability_id: str,
    implementation_id: str,
    domain_id: str,
) -> ControlDefinition:
    return ControlDefinition(
        control_id=control_id,
        version="1",
        title=control_id,
        capability_id=capability_id,
        implementation_id=implementation_id,
        security_domain_ids=(domain_id,),
        detection_scope="bounded test detection",
        exclusions=("runtime behavior",),
        reference_ids=(),
        source_path=Path("controls.yaml"),
    )


def test_matrix_projects_framework_language_and_global_contracts():
    domains = {
        "DOMAIN-INJECTION-001": _domain("DOMAIN-INJECTION-001", "Injection"),
        "DOMAIN-SECRETS-001": _domain("DOMAIN-SECRETS-001", "Secrets"),
    }
    capabilities = {
        "control.python": _capability(
            "control.python",
            "SEC-PYTHON-001",
            languages=frozenset({"Python"}),
        ),
        "control.fastapi": _capability(
            "control.fastapi",
            "SEC-FASTAPI-001",
            languages=frozenset({"Python"}),
            frameworks=frozenset({"FastAPI"}),
        ),
        "adapter.global": _capability(
            "adapter.global",
            "SEC-GLOBAL-001",
            kind="ADAPTER",
        ),
    }
    controls = {
        "CONTROL-PYTHON-001": _control(
            "CONTROL-PYTHON-001",
            "control.python",
            "SEC-PYTHON-001",
            "DOMAIN-INJECTION-001",
        ),
        "CONTROL-FASTAPI-001": _control(
            "CONTROL-FASTAPI-001",
            "control.fastapi",
            "SEC-FASTAPI-001",
            "DOMAIN-INJECTION-001",
        ),
        "CONTROL-GLOBAL-001": _control(
            "CONTROL-GLOBAL-001",
            "adapter.global",
            "SEC-GLOBAL-001",
            "DOMAIN-SECRETS-001",
        ),
    }

    matrix = build_assurance_matrix(
        CapabilityRegistry(
            schema_version=1,
            catalog_version="1",
            catalog_digest="cap-digest",
            capabilities=capabilities,
        ),
        SecurityDomainCatalog(
            schema_version=1,
            catalog_version="2",
            catalog_digest="domain-digest",
            domains=domains,
            controls=controls,
        ),
    )

    assert matrix.technologies == (
        "GLOBAL",
        "language:Python",
        "framework:FastAPI",
    )
    assert matrix.cell("DOMAIN-INJECTION-001", "language:Python").contract_count == 1
    assert matrix.cell("DOMAIN-INJECTION-001", "framework:FastAPI").contract_count == 1
    assert matrix.cell("DOMAIN-INJECTION-001", "GLOBAL") is None
    assert matrix.cell("DOMAIN-SECRETS-001", "GLOBAL").adapter_count == 1


def test_framework_capability_is_not_duplicated_into_language_column():
    domain = _domain("DOMAIN-AUTHORIZATION-001", "Authorization")
    capability = _capability(
        "control.fastapi-authz",
        "SEC-FASTAPI-AUTHZ-001",
        languages=frozenset({"Python"}),
        frameworks=frozenset({"FastAPI"}),
    )
    control = _control(
        "CONTROL-FASTAPI-AUTHZ-001",
        capability.capability_id,
        capability.implementation_id,
        domain.domain_id,
    )

    matrix = build_assurance_matrix(
        CapabilityRegistry(1, "1", "cap", {capability.capability_id: capability}),
        SecurityDomainCatalog(
            1,
            "1",
            "domain",
            {domain.domain_id: domain},
            {control.control_id: control},
        ),
    )

    assert matrix.cell(domain.domain_id, "framework:FastAPI") is not None
    assert matrix.cell(domain.domain_id, "language:Python") is None


def test_matrix_fails_closed_on_unknown_capability():
    domain = _domain("DOMAIN-INJECTION-001", "Injection")
    control = _control(
        "CONTROL-BROKEN-001",
        "missing.capability",
        "SEC-BROKEN-001",
        domain.domain_id,
    )

    with pytest.raises(ValueError, match="unknown capability"):
        build_assurance_matrix(
            CapabilityRegistry(1, "1", "cap", {}),
            SecurityDomainCatalog(
                1,
                "1",
                "domain",
                {domain.domain_id: domain},
                {control.control_id: control},
            ),
        )


def test_markdown_renderer_exposes_contract_counts_and_details():
    domain = _domain("DOMAIN-INJECTION-001", "Injection")
    capability = _capability(
        "control.python",
        "SEC-PYTHON-001",
        languages=frozenset({"Python"}),
    )
    control = _control(
        "CONTROL-PYTHON-001",
        capability.capability_id,
        capability.implementation_id,
        domain.domain_id,
    )
    matrix = build_assurance_matrix(
        CapabilityRegistry(1, "1", "cap", {capability.capability_id: capability}),
        SecurityDomainCatalog(
            1,
            "1",
            "domain",
            {domain.domain_id: domain},
            {control.control_id: control},
        ),
    )

    rendered = render_assurance_matrix_markdown(matrix)

    assert "# Domain Assurance Matrix" in rendered
    assert "`DOMAIN-INJECTION-001` Injection" in rendered
    assert "language:Python" in rendered
    assert "`CONTROL-PYTHON-001`" in rendered
    assert "diagnostic" in rendered
