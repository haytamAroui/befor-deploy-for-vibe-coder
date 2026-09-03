from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_ssrf import FastApiDirectUrlSsrfControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    return FastApiDirectUrlSsrfControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_fastapi_string_parameter_to_requests_get_is_reported(tmp_path: Path):
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

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-FASTAPI-SSRF-001"
    assert finding.location is not None
    assert finding.location.start_line == 8
    assert finding.evidence == {
        "artifact": "python",
        "flow": "fastapi_direct_parameter_to_http_client",
        "sink_family": "requests_or_httpx_module_call",
    }


def test_direct_fastapi_string_parameter_to_httpx_keyword_url_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import httpx

app = FastAPI()

@app.post("/fetch")
def fetch(target: str):
    return httpx.post(url=target)
''',
    )

    assert {finding.rule_id for finding in result.findings} == {"SEC-FASTAPI-SSRF-001"}


def test_requests_request_second_positional_url_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/proxy")
def proxy(destination: str):
    return requests.request("GET", destination)
''',
    )

    assert len(result.findings) == 1


def test_literal_destination_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/health")
def health():
    return requests.get("https://example.com/health")
''',
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_one_local_alias_is_out_of_scope(tmp_path: Path):
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

    assert result.findings == ()


def test_concatenated_url_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/preview")
def preview(host: str):
    return requests.get("https://" + host)
''',
    )

    assert result.findings == ()


def test_depends_string_parameter_is_not_treated_as_direct_user_input(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import Depends, FastAPI
import requests

app = FastAPI()

def current_service_url() -> str:
    return "https://service.example"

@app.get("/preview")
def preview(url: str = Depends(current_service_url)):
    return requests.get(url)
''',
    )

    assert result.findings == ()


def test_import_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''from fastapi import FastAPI
import requests as rq

app = FastAPI()

@app.get("/preview")
def preview(url: str):
    return rq.get(url)
''',
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_non_fastapi_python_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        '''import requests

def fetch(url: str):
    return requests.get(url)
''',
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
