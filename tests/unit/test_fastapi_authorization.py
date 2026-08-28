from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_authorization import FastApiAuthorizationDeclarationControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "routes.py").write_text(source, encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    return FastApiAuthorizationDeclarationControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def test_authentication_without_authorization_marker_is_a_finding(tmp_path: Path):
    result = _run(
        tmp_path,
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def get_current_user(): ...\n"
        "@app.post('/accounts')\n"
        "def create_account(user=Depends(get_current_user)):\n"
        "    return {'ok': True}\n",
    )

    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-API-AUTHZ-001"
    assert finding.evidence == {
        "artifact": "python",
        "issue": "authentication_without_authorization_marker",
    }
    assert finding.location.path == "routes.py"
    assert finding.location.start_line == 5
    assert "/accounts" not in finding.message
    assert "create_account" not in finding.message


def test_recognized_authorization_dependency_is_safe_for_this_control(tmp_path: Path):
    result = _run(
        tmp_path,
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def get_current_user(): ...\n"
        "def require_account_owner(): ...\n"
        "@app.post('/accounts')\n"
        "def create_account(user=Depends(get_current_user), owner=Depends(require_account_owner)):\n"
        "    return {'ok': True}\n",
    )

    assert result.execution.status.value == "COMPLETED"
    assert result.findings == ()


@pytest.mark.parametrize(
    "source",
    (
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def get_current_user(): ...\n"
        "route_path = '/accounts'\n"
        "@app.post(route_path)\n"
        "def create_account(user=Depends(get_current_user)):\n"
        "    return {'ok': True}\n",
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "def load_user_context(): ...\n"
        "@app.post('/accounts')\n"
        "def create_account(user=Depends(load_user_context)):\n"
        "    return {'ok': True}\n",
        "class App:\n"
        "    def post(self, path):\n"
        "        return lambda function: function\n"
        "app = App()\n"
        "def get_current_user(): ...\n"
        "@app.post('/accounts')\n"
        "def create_account(user=Depends(get_current_user)):\n"
        "    return {'ok': True}\n",
    ),
)
def test_dynamic_non_authenticated_or_non_fastapi_shapes_are_excluded(tmp_path: Path, source: str):
    result = _run(tmp_path, source)

    assert result.findings == ()


def test_invalid_python_is_fail_closed(tmp_path: Path):
    (tmp_path / "routes.py").write_text("from fastapi import FastAPI\n@", encoding="utf-8")
    inventory = collect_inventory(tmp_path)

    with pytest.raises(ValueError, match="Unable to parse Python source"):
        FastApiAuthorizationDeclarationControl().run(
            ControlContext(repository_root=tmp_path, inventory=inventory)
        )
