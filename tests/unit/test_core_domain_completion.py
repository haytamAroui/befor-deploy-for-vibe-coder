from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.core_domain_completion import (
    FastApiApiAssuranceControl,
    FastApiAuthenticationBoundaryControl,
    FastApiEndpointAccessControl,
    FastApiStripeWebhookSignatureControl,
    PythonDatabaseTransportControl,
    SecurityTestEvidenceControl,
)
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, control, files: dict[str, str]):
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return control.run(ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path)))


def test_authentication_and_endpoint_contracts_reuse_bounded_fastapi_route_parser(tmp_path: Path):
    source = """from fastapi import FastAPI
app = FastAPI()
@app.post('/account')
def update():
    return {'ok': True}
"""
    auth = _run(tmp_path, FastApiAuthenticationBoundaryControl(), {"app.py": source})
    endpoint = FastApiEndpointAccessControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )

    assert {finding.rule_id for finding in auth.findings} == {"SEC-AUTH-FASTAPI-001"}
    assert {finding.rule_id for finding in endpoint.findings} == {"SEC-ENDPOINT-FASTAPI-001"}


def test_api_assurance_contract_reuses_bounded_body_typing_parser(tmp_path: Path):
    result = _run(
        tmp_path,
        FastApiApiAssuranceControl(),
        {
            "app.py": """from fastapi import FastAPI
app = FastAPI()
@app.post('/items')
def create(payload: dict):
    return payload
"""
        },
    )

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC-API-ASSURANCE-FASTAPI-001"


def test_database_transport_literal_dsn_disable_is_reported_without_dsn_evidence(tmp_path: Path):
    result = _run(
        tmp_path,
        PythonDatabaseTransportControl(),
        {
            "db.py": """from sqlalchemy import create_engine
engine = create_engine('postgresql://user:secret@db/app?sslmode=disable')
"""
        },
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-DATABASE-TRANSPORT-PYTHON-001"
    assert finding.evidence == {
        "artifact": "python_database_client_call",
        "client": "sqlalchemy",
        "transport_policy": "tls_disabled",
        "configuration_form": "literal_dsn",
    }
    assert "secret" not in str(finding.evidence)


def test_database_transport_secure_literal_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        PythonDatabaseTransportControl(),
        {
            "db.py": """from sqlalchemy import create_engine
engine = create_engine('postgresql://db/app?sslmode=require')
"""
        },
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_database_transport_psycopg_keyword_disable_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        PythonDatabaseTransportControl(),
        {"db.py": "import psycopg\nconn = psycopg.connect('dbname=app', sslmode='disable')\n"},
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence["configuration_form"] == "literal_keyword"


def test_security_test_evidence_present_is_completed_without_finding(tmp_path: Path):
    result = _run(
        tmp_path,
        SecurityTestEvidenceControl(),
        {
            "app.py": "print('app')\n",
            "tests/test_auth_security.py": "def test_auth_security():\n    assert True\n",
        },
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.execution.metadata["security_test_evidence"] == "present"
    assert result.findings == ()


def test_security_test_evidence_absence_is_assurance_gap(tmp_path: Path):
    result = _run(
        tmp_path,
        SecurityTestEvidenceControl(),
        {"app.py": "print('app')\n", "tests/test_math.py": "def test_math():\n    assert 1 + 1 == 2\n"},
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC-SECURITY-TESTING-EVIDENCE-001"


def test_stripe_webhook_without_direct_construct_event_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        FastApiStripeWebhookSignatureControl(),
        {
            "payments.py": """import stripe
from fastapi import APIRouter, Request
router = APIRouter()
@router.post('/stripe/webhook')
async def webhook(request: Request):
    payload = await request.body()
    return {'ok': True}
"""
        },
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC-PAYMENT-STRIPE-WEBHOOK-001"


def test_stripe_webhook_with_direct_construct_event_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        FastApiStripeWebhookSignatureControl(),
        {
            "payments.py": """import stripe
from fastapi import APIRouter, Request
router = APIRouter()
@router.post('/stripe/webhook')
async def webhook(request: Request):
    payload = await request.body()
    event = stripe.Webhook.construct_event(payload, request.headers['Stripe-Signature'], 'secret')
    return {'type': event.type}
"""
        },
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_payment_control_without_stripe_is_not_applicable(tmp_path: Path):
    result = _run(tmp_path, FastApiStripeWebhookSignatureControl(), {"app.py": "print('no stripe')\n"})

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
