from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_input import FastApiInputValidationControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "routes.py").write_text(source, encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    return FastApiInputValidationControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def test_direct_untyped_mutating_body_parameter_produces_finding(tmp_path: Path):
    result = _run(
        tmp_path,
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/accounts')\n"
        "def create_account(payload: dict):\n"
        "    return payload\n",
    )

    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "Mutating FastAPI route accepts an untyped body parameter"
    assert finding.evidence == {"artifact": "python", "issue": "untyped_fastapi_body"}
    assert finding.location.path == "routes.py"
    assert finding.location.start_line == 4


def test_explicit_model_and_non_mutating_routes_are_safe(tmp_path: Path):
    result = _run(
        tmp_path,
        "from typing import Any\n"
        "from fastapi import FastAPI\n"
        "from pydantic import BaseModel\n"
        "app = FastAPI()\n"
        "class Account(BaseModel):\n"
        "    name: str\n"
        "@app.post('/accounts')\n"
        "def create_account(payload: Account):\n"
        "    return payload\n"
        "@app.get('/accounts')\n"
        "def list_accounts(payload: Any):\n"
        "    return []\n",
    )

    assert result.execution.status.value == "COMPLETED"
    assert result.findings == ()


@pytest.mark.parametrize(
    "source",
    (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/accounts')\n"
        "def create_account(payload: dict[str, str]):\n"
        "    return payload\n",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/accounts')\n"
        "def create_account(payload: ModelAlias):\n"
        "    return payload\n",
    ),
)
def test_dynamic_or_explicitly_aliased_input_shapes_are_excluded(tmp_path: Path, source: str):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "COMPLETED"
    assert result.findings == ()


def test_dynamic_route_decorator_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "route = '/accounts'\n"
        "@app.post(route)\n"
        "def create_account(payload: dict):\n"
        "    return payload\n",
    )

    assert result.execution.status.value == "NOT_APPLICABLE"
    assert result.findings == ()


def test_non_fastapi_decorator_is_not_an_input_validation_finding(tmp_path: Path):
    result = _run(
        tmp_path,
        "class App:\n"
        "    def post(self, path):\n"
        "        return lambda function: function\n"
        "app = App()\n"
        "@app.post('/accounts')\n"
        "def create_account(payload: dict):\n"
        "    return payload\n",
    )

    assert result.execution.status.value == "NOT_APPLICABLE"
    assert result.findings == ()


def test_control_is_not_applicable_without_literal_fastapi_routes(tmp_path: Path):
    result = _run(tmp_path, "def helper(payload: dict):\n    return payload\n")

    assert result.execution.status.value == "NOT_APPLICABLE"
    assert result.findings == ()


def test_invalid_python_is_a_fail_closed_error(tmp_path: Path):
    (tmp_path / "routes.py").write_text("from fastapi import FastAPI\n@", encoding="utf-8")
    inventory = collect_inventory(tmp_path)

    with pytest.raises(ValueError, match="Unable to parse Python source"):
        FastApiInputValidationControl().run(
            ControlContext(repository_root=tmp_path, inventory=inventory)
        )
