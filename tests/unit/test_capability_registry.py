from pathlib import Path

import pytest

from before_deploy.capabilities import (
    load_builtin_capability_registry,
    load_capability_registry,
)
from before_deploy.policy import load_policy


REPOSITORY = Path(__file__).parents[2]


def test_builtin_registry_is_versioned_and_contains_only_approved_implementations():
    first = load_builtin_capability_registry()
    second = load_builtin_capability_registry()

    assert first.schema_version == 1
    assert first.catalog_version == "0.34.0"
    assert first.catalog_digest == second.catalog_digest
    assert len(first.capabilities) == 50
    assert first.definition_for_implementation("SEC-NEXT-ENV-001").capability_id == (
        "control.native.nextjs-public-env"
    )
    next_error = first.definition_for_implementation("SEC-NEXT-ERROR-STACK-001")
    assert next_error.capability_id == "control.native.nextjs-route-stack-response"
    assert next_error.frameworks == frozenset({"Next.js"})
    assert next_error.languages == frozenset({"JavaScript", "TypeScript"})
    assert first.definition_for_implementation("SEC-GO-TLS-001").capability_id == (
        "control.native.go-tls-verification"
    )
    go_snapshot = first.definition_for_implementation("SEC-GO-VULN-001")
    assert go_snapshot.capability_id == "control.native.go-vulnerability-snapshot"
    assert go_snapshot.version == "0.2.0"
    assert first.definition_for_implementation("SEC-NEXT-ACTION-001").capability_id == (
        "control.native.nextjs-server-action-local-guard"
    )
    assert first.definition_for_implementation("SEC-NEXT-INLINE-ACTION-001").capability_id == (
        "control.native.nextjs-inline-server-action-local-guard"
    )
    next_ssrf = first.definition_for_implementation("SEC-NEXT-SSRF-001")
    assert next_ssrf.capability_id == "control.native.nextjs-direct-query-fetch-ssrf"
    assert next_ssrf.frameworks == frozenset({"Next.js"})
    next_ssrf_alias = first.definition_for_implementation("SEC-NEXT-SSRF-ALIAS-001")
    assert next_ssrf_alias.capability_id == "control.native.nextjs-single-alias-query-fetch-ssrf"
    assert next_ssrf_alias.frameworks == frozenset({"Next.js"})
    assert first.definition_for_implementation("SEC-TRIVY-CONFIG-001").capability_id == (
        "adapter.trivy-config-isolated"
    )
    assert first.definition_for_implementation("SEC-SAST-SQL-ALIAS-001").capability_id == (
        "control.native.python-sql-single-local-alias"
    )
    fastapi_routes = first.definition_for_implementation("SEC-API-001")
    assert fastapi_routes.capability_id == "control.native.fastapi-api"
    assert fastapi_routes.version == "0.3.0"
    fastapi_ssrf = first.definition_for_implementation("SEC-FASTAPI-SSRF-001")
    assert fastapi_ssrf.capability_id == "control.native.fastapi-direct-url-ssrf"
    assert fastapi_ssrf.frameworks == frozenset({"FastAPI"})
    fastapi_ssrf_alias = first.definition_for_implementation("SEC-FASTAPI-SSRF-ALIAS-001")
    assert fastapi_ssrf_alias.capability_id == "control.native.fastapi-single-alias-ssrf"
    assert fastapi_ssrf_alias.frameworks == frozenset({"FastAPI"})
    fastapi_session = first.definition_for_implementation("SEC-FASTAPI-SESSION-COOKIE-001")
    assert fastapi_session.capability_id == "control.native.fastapi-session-cookie"
    assert fastapi_session.frameworks == frozenset({"FastAPI"})
    assert fastapi_session.languages == frozenset({"Python"})
    php_laravel = first.definition_for_implementation("SEC-PHP-LARAVEL-COMPOSER-LOCK-001")
    assert php_laravel.capability_id == "control.native.php-laravel-composer-lock"
    assert php_laravel.version == "0.1.0"
    rust_cargo = first.definition_for_implementation("SEC-RUST-CARGO-LOCK-001")
    assert rust_cargo.capability_id == "control.native.rust-cargo-lock"
    assert rust_cargo.version == "0.1.0"
    ruby_rails = first.definition_for_implementation("SEC-RUBY-RAILS-GEMFILE-LOCK-001")
    assert ruby_rails.capability_id == "control.native.ruby-rails-gemfile-lock"
    assert ruby_rails.version == "0.1.0"
    docker_compose = first.definition_for_implementation("SEC-COMPOSE-PRIVILEGED-001")
    assert docker_compose.capability_id == "control.native.docker-compose-privileged"
    assert docker_compose.version == "0.1.0"
    data_integrity = first.definition_for_implementation("SEC-DATA-INTEGRITY-001")
    assert data_integrity.capability_id == "control.native.python-data-integrity"
    assert data_integrity.version == "0.1.0"
    sensitive_data = first.definition_for_implementation("SEC-SENSITIVE-DATA-PYTHON-001")
    assert sensitive_data.capability_id == "control.native.python-sensitive-data"
    assert sensitive_data.version == "0.1.0"
    fastapi_authz = first.definition_for_implementation("SEC-API-AUTHZ-001")
    assert fastapi_authz.capability_id == "control.native.fastapi-authorization"
    assert fastapi_authz.version == "0.1.0"
    fastapi_input = first.definition_for_implementation("SEC-API-INPUT-001")
    assert fastapi_input.capability_id == "control.native.fastapi-input-validation"
    assert fastapi_input.version == "0.1.0"
    fastapi_upload = first.definition_for_implementation("SEC-API-UPLOAD-001")
    assert fastapi_upload.capability_id == "control.native.fastapi-file-upload"
    assert fastapi_upload.version == "0.1.0"
    spring_actuator = first.definition_for_implementation("SEC-SPRING-ACTUATOR-001")
    assert spring_actuator.capability_id == "control.native.spring-actuator"
    assert spring_actuator.frameworks == frozenset({"Spring"})
    spring_cors = first.definition_for_implementation("SEC-SPRING-CORS-001")
    assert spring_cors.capability_id == "control.native.spring-cors"
    assert spring_cors.frameworks == frozenset({"Spring"})
    spring_jpa = first.definition_for_implementation("SEC-SPRING-JPA-NATIVE-QUERY-001")
    assert spring_jpa.capability_id == "control.native.spring-jpa-native-query-injection"
    assert spring_jpa.frameworks == frozenset({"Spring"})
    assert spring_jpa.languages == frozenset({"Java"})
    spring_security = first.definition_for_implementation("SEC-SPRING-SECURITY-PERMIT-ALL-001")
    assert spring_security.capability_id == "control.native.spring-security-permit-all"
    assert spring_security.frameworks == frozenset({"Spring"})
    assert spring_security.languages == frozenset({"Java"})
    assert first.definition_for_implementation("SEC-AUTH-FASTAPI-001").capability_id == (
        "control.native.fastapi-authentication-domain"
    )
    assert first.definition_for_implementation("SEC-ENDPOINT-FASTAPI-001").capability_id == (
        "control.native.fastapi-endpoint-domain"
    )
    assert first.definition_for_implementation("SEC-DATABASE-TRANSPORT-PYTHON-001").capability_id == (
        "control.native.python-database-transport"
    )
    assert first.definition_for_implementation("SEC-API-ASSURANCE-FASTAPI-001").capability_id == (
        "control.native.fastapi-api-assurance-domain"
    )
    assert first.definition_for_implementation("SEC-SECURITY-TESTING-EVIDENCE-001").capability_id == (
        "control.native.security-testing-evidence"
    )
    assert first.definition_for_implementation("SEC-PAYMENT-STRIPE-WEBHOOK-001").capability_id == (
        "control.native.payment-stripe-webhook"
    )
    assert first.definition_for_implementation("SEC-UNREGISTERED-001") is None


def test_every_configured_policy_control_has_one_approved_capability_definition():
    registry = load_builtin_capability_registry()
    registered = {definition.implementation_id for definition in registry.capabilities.values()}

    for policy_path in sorted((REPOSITORY / "rules").glob("*.yaml")):
        profile = load_policy(policy_path)
        assert set(profile.controls) <= registered, policy_path.name


def test_registry_rejects_unknown_executable_field(tmp_path):
    _write_registry(tmp_path, """schema_version: 1
id: control.example
version: "0.1.0"
implementation_id: SEC-SECRET-001
kind: CONTROL
title: Example
applies_when: {}
security_domains: [Secrets]
exclusions: []
command: curl https://example.test
""")
    with pytest.raises(ValueError, match="Unsupported fields"):
        load_capability_registry(tmp_path)


def test_registry_rejects_url_or_command_marker_in_permitted_text_field(tmp_path):
    _write_registry(tmp_path, """schema_version: 1
id: control.example
version: "0.1.0"
implementation_id: SEC-SECRET-001
kind: CONTROL
title: https://untrusted.example/command
applies_when: {}
security_domains: [Secrets]
exclusions: []
""")
    with pytest.raises(ValueError, match="forbidden executable or URL marker"):
        load_capability_registry(tmp_path)


def test_registry_rejects_unapproved_implementation_and_duplicate_yaml_keys(tmp_path):
    _write_registry(tmp_path, """schema_version: 1
id: control.example
version: "0.1.0"
implementation_id: SEC-UNAPPROVED-001
kind: CONTROL
title: Example
applies_when: {}
security_domains: [Secrets]
exclusions: []
""")
    with pytest.raises(ValueError, match="unapproved implementation"):
        load_capability_registry(tmp_path)

    _write_registry(tmp_path, """schema_version: 1
id: control.example
id: control.duplicate
version: "0.1.0"
implementation_id: SEC-SECRET-001
kind: CONTROL
title: Example
applies_when: {}
security_domains: [Secrets]
exclusions: []
""")
    with pytest.raises(ValueError, match="Unable to load capability manifest"):
        load_capability_registry(tmp_path)


def _write_registry(directory, manifest: str) -> None:
    (directory / "catalog.yaml").write_text(
        """schema_version: 1
catalog_version: "test"
manifests:
  - example.yaml
""",
        encoding="utf-8",
    )
    (directory / "example.yaml").write_text(manifest, encoding="utf-8")
