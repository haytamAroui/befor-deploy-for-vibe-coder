from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_session_cookie import FastApiUnsafeSessionCookieControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


IMPORTS = """from fastapi import FastAPI, Response
app = FastAPI()
"""


def _run(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return FastApiUnsafeSessionCookieControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_explicit_httponly_false_on_session_cookie_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/login")
def login(response: Response):
    response.set_cookie(key="session", value="token", httponly=False, secure=True)
    return {"ok": True}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-FASTAPI-SESSION-COOKIE-001"
    assert finding.evidence["cookie"] == "session"
    assert finding.evidence["unsafe_options"] == "httponly=False"


def test_explicit_secure_false_on_auth_cookie_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/login")
async def login(response: Response):
    response.set_cookie("auth_token", "value", httponly=True, secure=False)
    return {"ok": True}
""",
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence["unsafe_options"] == "secure=False"


def test_explicit_secure_flags_are_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/login")
def login(response: Response):
    response.set_cookie("session", "value", httponly=True, secure=True, samesite="lax")
    return {"ok": True}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_missing_flags_are_not_inferred_as_unsafe(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/login")
def login(response: Response):
    response.set_cookie("session", "value")
    return {"ok": True}
""",
    )

    assert result.findings == ()


def test_non_session_cookie_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/preferences")
def preferences(response: Response):
    response.set_cookie("theme", "dark", httponly=False, secure=False)
    return {"ok": True}
""",
    )

    assert result.findings == ()


def test_response_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/login")
def login(response: Response):
    target = response
    target.set_cookie("session", "value", httponly=False)
    return {"ok": True}
""",
    )

    assert result.findings == ()


def test_unannotated_response_parameter_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
@app.post("/login")
def login(response):
    response.set_cookie("session", "value", httponly=False)
    return {"ok": True}
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_non_fastapi_python_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        """
def login(response):
    response.set_cookie("session", "value", httponly=False)
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
