from pathlib import Path

import pytest

from before_deploy.capabilities import load_builtin_capability_registry
from before_deploy.domains import (
    load_builtin_security_domain_catalog,
    load_security_domain_catalog,
)


APPROVED_REFERENCE_URL = (
    "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
)


def test_builtin_domain_catalog_is_versioned_deterministic_and_maps_only_real_capabilities():
    catalog = load_builtin_security_domain_catalog()
    second = load_builtin_security_domain_catalog()
    registry = load_builtin_capability_registry()

    assert catalog.schema_version == 1
    assert catalog.catalog_version == "0.7.0"
    assert catalog.catalog_digest == second.catalog_digest
    assert len(catalog.domains) == 30
    assert len(catalog.controls) == 21
    assert catalog.domains["DOMAIN-SSRF-001"].title == "Server-side request forgery"
    assert {
        control.capability_id for control in catalog.controls.values()
    } == set(registry.capabilities)
    assert all(
        registry.capabilities[control.capability_id].implementation_id == control.implementation_id
        for control in catalog.controls.values()
    )


def test_domain_catalog_exposes_a_unique_contract_for_each_registered_implementation():
    catalog = load_builtin_security_domain_catalog()

    contract = catalog.control_for_implementation("SEC-GO-TLS-001")

    assert contract is not None
    assert contract.control_id == "CONTROL-TRANSPORT-GO-TLS-001"
    assert contract.capability_id == "control.native.go-tls-verification"
    assert contract.security_domain_ids == ("DOMAIN-TRANSPORT-SECURITY-001",)
    trivy_contract = catalog.control_for_implementation("SEC-TRIVY-CONFIG-001")
    assert trivy_contract is not None
    assert trivy_contract.control_id == "CONTROL-CONTAINER-IAC-TRIVY-CONFIG-001"
    assert trivy_contract.security_domain_ids == (
        "DOMAIN-CONTAINER-SECURITY-001",
        "DOMAIN-IAC-SECURITY-001",
    )
    assert catalog.control_for_implementation("SEC-NOT-REGISTERED-001") is None


def test_domain_catalog_is_informational_and_exposes_registry_mapping(tmp_path):
    catalog = load_builtin_security_domain_catalog()
    registry = load_builtin_capability_registry()
    from before_deploy.models import ProjectProfile

    profile = ProjectProfile(
        languages=(),
        frameworks=(),
        package_managers=(),
        signals={},
        coverage_gaps=(),
    )

    active = catalog.domains_for_profile(profile, frozenset({"REQUIREMENT-EXTERNAL-URL-FETCH"}))

    assert [item.domain_id for item in active] == ["DOMAIN-SECRETS-001", "DOMAIN-SSRF-001"]
    assert [item.capability_id for item in catalog.controls_for_domain("DOMAIN-SSRF-001")] == [
        "adapter.gosec-go-module"
    ]
    assert registry.definition_for_implementation("SEC-UNREGISTERED-001") is None


def test_domain_catalog_rejects_unknown_executable_metadata_and_unknown_domain_reference(tmp_path):
    _write_catalog(
        tmp_path,
        domain_extra="\n    command: curl https://untrusted.example/check",
    )
    with pytest.raises(ValueError, match="Unsupported fields"):
        load_security_domain_catalog(
            tmp_path, capability_registry=load_builtin_capability_registry()
        )

    _write_catalog(tmp_path, control_domain="DOMAIN-NOT-REGISTERED-001")
    with pytest.raises(ValueError, match="unknown security domains"):
        load_security_domain_catalog(
            tmp_path, capability_registry=load_builtin_capability_registry()
        )


def test_domain_catalog_rejects_unapproved_reference_and_duplicate_yaml_key(tmp_path):
    _write_catalog(tmp_path, reference_url="https://untrusted.example/reference")
    with pytest.raises(ValueError, match="URL is not approved"):
        load_security_domain_catalog(
            tmp_path, capability_registry=load_builtin_capability_registry()
        )

    _write_catalog(tmp_path, duplicate_domain_id=True)
    with pytest.raises(ValueError, match="Unable to load security domain manifest bundle"):
        load_security_domain_catalog(
            tmp_path, capability_registry=load_builtin_capability_registry()
        )


def _write_catalog(
    directory: Path,
    *,
    domain_extra: str = "",
    control_domain: str = "DOMAIN-EXAMPLE-001",
    reference_url: str = APPROVED_REFERENCE_URL,
    duplicate_domain_id: bool = False,
) -> None:
    (directory / "catalog.yaml").write_text(
        """schema_version: 1
catalog_version: "test"
references:
  REF-EXAMPLE:
    title: Example reference
    url: {reference_url}
domain_manifests:
  - domains.yaml
control_manifests:
  - controls.yaml
""".format(reference_url=reference_url),
        encoding="utf-8",
    )
    duplicate = "\n    id: DOMAIN-EXAMPLE-DUPLICATE-001" if duplicate_domain_id else ""
    (directory / "domains.yaml").write_text(
        """schema_version: 1
domains:
  - id: DOMAIN-EXAMPLE-001{duplicate}
    version: "0.1.0"
    title: Example security domain
    category: APPLICATION_SECURITY
    description: Example only.
    applies_when:
      repository_wide: true
    references:
      - REF-EXAMPLE
    exclusions: []{domain_extra}
""".format(domain_extra=domain_extra, duplicate=duplicate),
        encoding="utf-8",
    )
    (directory / "controls.yaml").write_text(
        """schema_version: 1
controls:
  - id: CONTROL-EXAMPLE-001
    version: "0.1.0"
    title: Example control contract
    capability_id: control.native.secrets
    implementation_id: SEC-SECRET-001
    security_domains:
      - {control_domain}
    detection_scope: Example scope only.
    exclusions: []
    references:
      - REF-EXAMPLE
""".format(control_domain=control_domain),
        encoding="utf-8",
    )
