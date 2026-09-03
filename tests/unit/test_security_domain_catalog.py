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
    assert catalog.catalog_version == "0.27.0"
    assert catalog.catalog_digest == second.catalog_digest
    assert len(catalog.domains) == 30
    assert len(catalog.controls) == 38
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
    sql_alias_contract = catalog.control_for_implementation("SEC-SAST-SQL-ALIAS-001")
    assert sql_alias_contract is not None
    assert sql_alias_contract.control_id == "CONTROL-INJECTION-PYTHON-SQL-SINGLE-ALIAS-001"
    assert sql_alias_contract.security_domain_ids == ("DOMAIN-INJECTION-001",)
    inline_action_contract = catalog.control_for_implementation("SEC-NEXT-INLINE-ACTION-001")
    assert inline_action_contract is not None
    assert inline_action_contract.control_id == "CONTROL-AUTHORIZATION-NEXT-INLINE-SERVER-ACTION-001"
    assert inline_action_contract.security_domain_ids == ("DOMAIN-AUTHORIZATION-001",)
    go_snapshot_contract = catalog.control_for_implementation("SEC-GO-VULN-001")
    assert go_snapshot_contract is not None
    assert go_snapshot_contract.control_id == "CONTROL-SUPPLY-GO-VULNERABILITY-SNAPSHOT-001"
    assert go_snapshot_contract.version == "0.2.0"
    fastapi_contract = catalog.control_for_implementation("SEC-API-001")
    assert fastapi_contract is not None
    assert fastapi_contract.control_id == "CONTROL-API-FASTAPI-001"
    assert fastapi_contract.version == "0.3.0"
    assert fastapi_contract.security_domain_ids == ("DOMAIN-API-SECURITY-001",)
    fastapi_ssrf_contract = catalog.control_for_implementation("SEC-FASTAPI-SSRF-001")
    assert fastapi_ssrf_contract is not None
    assert fastapi_ssrf_contract.control_id == "CONTROL-SSRF-FASTAPI-DIRECT-URL-001"
    assert fastapi_ssrf_contract.version == "0.1.0"
    assert fastapi_ssrf_contract.security_domain_ids == ("DOMAIN-SSRF-001",)
    fastapi_ssrf_alias_contract = catalog.control_for_implementation("SEC-FASTAPI-SSRF-ALIAS-001")
    assert fastapi_ssrf_alias_contract is not None
    assert fastapi_ssrf_alias_contract.control_id == "CONTROL-SSRF-FASTAPI-SINGLE-ALIAS-001"
    assert fastapi_ssrf_alias_contract.version == "0.1.0"
    assert fastapi_ssrf_alias_contract.security_domain_ids == ("DOMAIN-SSRF-001",)
    php_laravel_contract = catalog.control_for_implementation(
        "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    )
    assert php_laravel_contract is not None
    assert php_laravel_contract.control_id == "CONTROL-SUPPLY-PHP-LARAVEL-COMPOSER-LOCK-001"
    assert php_laravel_contract.version == "0.1.0"
    assert php_laravel_contract.security_domain_ids == ("DOMAIN-SUPPLY-CHAIN-001",)
    rust_cargo_contract = catalog.control_for_implementation("SEC-RUST-CARGO-LOCK-001")
    assert rust_cargo_contract is not None
    assert rust_cargo_contract.control_id == "CONTROL-SUPPLY-RUST-CARGO-LOCK-001"
    assert rust_cargo_contract.version == "0.1.0"
    assert rust_cargo_contract.security_domain_ids == ("DOMAIN-SUPPLY-CHAIN-001",)
    ruby_rails_contract = catalog.control_for_implementation(
        "SEC-RUBY-RAILS-GEMFILE-LOCK-001"
    )
    assert ruby_rails_contract is not None
    assert ruby_rails_contract.control_id == "CONTROL-SUPPLY-RUBY-RAILS-GEMFILE-LOCK-001"
    assert ruby_rails_contract.version == "0.1.0"
    assert ruby_rails_contract.security_domain_ids == ("DOMAIN-SUPPLY-CHAIN-001",)
    docker_compose_contract = catalog.control_for_implementation("SEC-COMPOSE-PRIVILEGED-001")
    assert docker_compose_contract is not None
    assert docker_compose_contract.control_id == "CONTROL-CONTAINER-DOCKER-COMPOSE-PRIVILEGED-001"
    assert docker_compose_contract.version == "0.1.0"
    assert docker_compose_contract.security_domain_ids == ("DOMAIN-CONTAINER-SECURITY-001",)
    fastapi_input_contract = catalog.control_for_implementation("SEC-API-INPUT-001")
    assert fastapi_input_contract is not None
    assert fastapi_input_contract.control_id == "CONTROL-API-FASTAPI-INPUT-001"
    assert fastapi_input_contract.version == "0.1.0"
    assert fastapi_input_contract.security_domain_ids == (
        "DOMAIN-INPUT-VALIDATION-001",
        "DOMAIN-API-SECURITY-001",
    )
    data_integrity_contract = catalog.control_for_implementation("SEC-DATA-INTEGRITY-001")
    assert data_integrity_contract is not None
    assert data_integrity_contract.control_id == "CONTROL-DATA-INTEGRITY-PYTHON-001"
    assert data_integrity_contract.version == "0.1.0"
    assert data_integrity_contract.security_domain_ids == ("DOMAIN-DATA-INTEGRITY-001",)
    sensitive_data_contract = catalog.control_for_implementation("SEC-SENSITIVE-DATA-PYTHON-001")
    assert sensitive_data_contract is not None
    assert sensitive_data_contract.control_id == "CONTROL-SENSITIVE-DATA-PYTHON-001"
    assert sensitive_data_contract.security_domain_ids == ("DOMAIN-SENSITIVE-DATA-001",)
    fastapi_authz_contract = catalog.control_for_implementation("SEC-API-AUTHZ-001")
    assert fastapi_authz_contract is not None
    assert fastapi_authz_contract.control_id == "CONTROL-API-FASTAPI-AUTHZ-001"
    assert fastapi_authz_contract.version == "0.1.0"
    assert fastapi_authz_contract.security_domain_ids == (
        "DOMAIN-AUTHORIZATION-001",
        "DOMAIN-API-SECURITY-001",
    )
    fastapi_upload_contract = catalog.control_for_implementation("SEC-API-UPLOAD-001")
    assert fastapi_upload_contract is not None
    assert fastapi_upload_contract.control_id == "CONTROL-API-FASTAPI-UPLOAD-001"
    assert fastapi_upload_contract.version == "0.1.0"
    assert fastapi_upload_contract.security_domain_ids == (
        "DOMAIN-FILE-UPLOAD-001",
        "DOMAIN-PATH-TRAVERSAL-001",
    )
    spring_contract = catalog.control_for_implementation("SEC-SPRING-ACTUATOR-001")
    assert spring_contract is not None
    assert spring_contract.control_id == "CONTROL-CONFIG-SPRING-ACTUATOR-001"
    assert spring_contract.version == "0.1.0"
    assert spring_contract.security_domain_ids == ("DOMAIN-PRODUCTION-CONFIGURATION-001",)
    spring_cors_contract = catalog.control_for_implementation("SEC-SPRING-CORS-001")
    assert spring_cors_contract is not None
    assert spring_cors_contract.control_id == "CONTROL-CORS-SPRING-CROSSORIGIN-001"
    assert spring_cors_contract.version == "0.1.0"
    assert spring_cors_contract.security_domain_ids == ("DOMAIN-CORS-001",)
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
        "adapter.gosec-go-module",
        "control.native.fastapi-direct-url-ssrf",
        "control.native.fastapi-single-alias-ssrf",
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
