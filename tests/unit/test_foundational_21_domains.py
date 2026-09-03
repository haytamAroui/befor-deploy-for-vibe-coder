from before_deploy.domains import load_builtin_security_domain_catalog


FOUNDATIONAL_21 = (
    "DOMAIN-AUTHENTICATION-001",
    "DOMAIN-AUTHORIZATION-001",
    "DOMAIN-ENDPOINT-SECURITY-001",
    "DOMAIN-INPUT-VALIDATION-001",
    "DOMAIN-INJECTION-001",
    "DOMAIN-CORS-001",
    "DOMAIN-SECRETS-001",
    "DOMAIN-SENSITIVE-DATA-001",
    "DOMAIN-ERROR-HANDLING-001",
    "DOMAIN-FILE-UPLOAD-001",
    "DOMAIN-DATABASE-SECURITY-001",
    "DOMAIN-DATA-INTEGRITY-001",
    "DOMAIN-API-ASSURANCE-001",
    "DOMAIN-OBSERVABILITY-001",
    "DOMAIN-SECURITY-TESTING-001",
    "DOMAIN-PRODUCTION-CONFIGURATION-001",
    "DOMAIN-SUPPLY-CHAIN-001",
    "DOMAIN-CICD-SECURITY-001",
    "DOMAIN-SESSION-SECURITY-001",
    "DOMAIN-API-SECURITY-001",
    "DOMAIN-PAYMENT-INTEGRATION-001",
)


def test_all_21_foundational_domains_have_at_least_one_real_control_contract():
    catalog = load_builtin_security_domain_catalog()

    assert len(FOUNDATIONAL_21) == 21
    assert len(set(FOUNDATIONAL_21)) == 21
    assert set(FOUNDATIONAL_21) <= set(catalog.domains)

    unmapped = {
        domain_id
        for domain_id in FOUNDATIONAL_21
        if not catalog.controls_for_domain(domain_id)
    }
    assert unmapped == set()


def test_core21_completion_contracts_close_the_previously_unmapped_domains():
    catalog = load_builtin_security_domain_catalog()

    expected = {
        "DOMAIN-AUTHENTICATION-001": "SEC-AUTH-FASTAPI-001",
        "DOMAIN-ENDPOINT-SECURITY-001": "SEC-ENDPOINT-FASTAPI-001",
        "DOMAIN-DATABASE-SECURITY-001": "SEC-DATABASE-TRANSPORT-PYTHON-001",
        "DOMAIN-API-ASSURANCE-001": "SEC-API-ASSURANCE-FASTAPI-001",
        "DOMAIN-SECURITY-TESTING-001": "SEC-SECURITY-TESTING-EVIDENCE-001",
        "DOMAIN-PAYMENT-INTEGRATION-001": "SEC-PAYMENT-STRIPE-WEBHOOK-001",
    }

    for domain_id, implementation_id in expected.items():
        assert implementation_id in {
            contract.implementation_id for contract in catalog.controls_for_domain(domain_id)
        }
