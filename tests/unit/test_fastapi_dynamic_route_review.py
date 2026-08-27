from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_routes import FastApiRouteAuthenticationControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "routes.py").write_text(source, encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    return FastApiRouteAuthenticationControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


@pytest.mark.parametrize(
    ("source", "reason", "line"),
    (
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "prefix = '/accounts'\n"
            "@app.post(prefix)\n"
            "def create_account():\n"
            "    return {}\n",
            "DYNAMIC_PATH",
            4,
        ),
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "methods = ['POST']\n"
            "@app.api_route('/accounts', methods=methods)\n"
            "def create_account():\n"
            "    return {}\n",
            "DYNAMIC_METHODS",
            4,
        ),
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.api_route('/accounts')\n"
            "def create_account():\n"
            "    return {}\n",
            "DYNAMIC_METHODS",
            3,
        ),
    ),
)
def test_fastapi_dynamic_route_structures_are_review_states_not_findings(
    tmp_path: Path, source: str, reason: str, line: int
):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "COMPLETED"
    assert result.execution.metadata == {
        "dynamic_route_review_status": "REVIEW_REQUIRED",
        "dynamic_route_review_count": "1",
        "dynamic_route_review_locations": f"routes.py:{line}:{reason}",
    }
    assert not result.findings


def test_fastapi_static_unauthenticated_route_still_produces_ordinary_finding(tmp_path: Path):
    result = _run(
        tmp_path,
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/accounts')\n"
        "def create_account():\n"
        "    return {}\n",
    )

    assert result.execution.metadata == {
        "dynamic_route_review_status": "NOT_REQUIRED",
        "dynamic_route_review_count": "0",
    }
    assert len(result.findings) == 1
    assert result.findings[0].evidence == {"route_path": "/accounts", "method": "POST"}


def test_fastapi_control_is_not_applicable_without_fastapi_or_route_decorators(tmp_path: Path):
    result = _run(tmp_path, "def helper():\n    return 'ok'\n")

    assert result.execution.status.value == "NOT_APPLICABLE"
    assert not result.execution.metadata
