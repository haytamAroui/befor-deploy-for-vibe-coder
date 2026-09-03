from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_ssrf_single_alias import FastApiSingleAliasSsrfControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return FastApiSingleAliasSsrfControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_one_local_alias_to_requests_get_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/preview")
def preview(url: str):
    target = url
    return requests.get(target)
''',
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-FASTAPI-SSRF-ALIAS-001"
    assert finding.location is not None
    assert finding.location.start_line == 9
    assert finding.evidence == {
        "artifact": "python",
        "flow": "fastapi_parameter_single_local_alias_to_http_client",
        "sink_family": "requests_or_httpx_module_call",
    }


def test_one_local_alias_to_httpx_keyword_url_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import httpx

app = FastAPI()

@app.post("/fetch")
def fetch(url: str):
    destination = url
    return httpx.post(url=destination)
''',
    )

    assert {finding.rule_id for finding in result.findings} == {"SEC-FASTAPI-SSRF-ALIAS-001"}


def test_direct_parameter_is_not_reported_by_alias_contract(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/preview")
def preview(url: str):
    return requests.get(url)
''',
    )

    assert result.findings == ()


def test_chained_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/preview")
def preview(url: str):
    first = url
    second = first
    return requests.get(second)
''',
    )

    assert result.findings == ()


def test_transformed_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/preview")
def preview(host: str):
    target = "https://" + host
    return requests.get(target)
''',
    )

    assert result.findings == ()


def test_alias_inside_branch_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/preview")
def preview(url: str, enabled: bool):
    if enabled:
        target = url
        return requests.get(target)
    return "disabled"
''',
    )

    assert result.findings == ()


def test_depends_parameter_is_not_treated_as_user_input(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import Depends, FastAPI
import requests

app = FastAPI()

def service_url() -> str:
    return "https://service.example"

@app.get("/preview")
def preview(url: str = Depends(service_url)):
    target = url
    return requests.get(target)
''',
    )

    assert result.findings == ()


def test_non_fastapi_python_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        '''import requests

def fetch(url: str):
    target = url
    return requests.get(target)
''',
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
