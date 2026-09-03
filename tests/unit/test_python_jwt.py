from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.python_jwt import PythonJwtSignatureVerificationControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus, Severity


def _run(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return PythonJwtSignatureVerificationControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_pyjwt_module_decode_with_signature_verification_disabled_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """
import jwt

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False})
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-JWT-PYTHON-VERIFY-001"
    assert finding.severity == Severity.BLOCKER
    assert finding.evidence["verification"] == "signature_disabled"


def test_python_jose_module_decode_with_signature_verification_disabled_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from jose import jwt

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_signature": False})
""",
    )

    assert len(result.findings) == 1


def test_direct_decode_import_with_signature_verification_disabled_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from jwt import decode

def decode_token(token, key):
    return decode(token, key, algorithms=["HS256"], options={"verify_signature": False})
""",
    )

    assert len(result.findings) == 1


def test_literal_signature_verification_true_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """
import jwt

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": True})
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_disabling_only_expiry_verification_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        """
import jwt

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": False})
""",
    )

    assert result.findings == ()


def test_options_variable_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        """
import jwt

OPTIONS = {"verify_signature": False}

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options=OPTIONS)
""",
    )

    assert result.findings == ()


def test_import_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        """
import jwt as tokenlib

def decode_token(token, key):
    return tokenlib.decode(token, key, options={"verify_signature": False})
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_unrelated_decode_function_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        """
def decode(token, key, options=None):
    return token

def load(token, key):
    return decode(token, key, options={"verify_signature": False})
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
