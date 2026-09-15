from __future__ import annotations

from json import dumps

import pytest

from before_deploy import platform_api
from before_deploy.platform_api import (
    BeforeDeployPlatformAPI,
    PlatformApiPolicy,
    PLATFORM_API_STATUS_COMPLETED,
)


def test_platform_api_capabilities_disable_governance_and_mutation_by_default():
    payload = BeforeDeployPlatformAPI().capabilities()
    operations = {item["name"]: item for item in payload["operations"]}

    assert operations["inspect"]["enabled"] is True
    assert operations["verify"]["enabled"] is True
    assert operations["release"]["enabled"] is True
    assert operations["approve"]["enabled"] is False
    assert operations["fix"]["enabled"] is False
    assert operations["regress"]["enabled"] is False
    assert operations["approve"]["mcp_default_exposed"] is False
    assert operations["regress"]["mcp_default_exposed"] is False
    assert payload["authority_contract"]["release_authority_operation"] == "release"
    assert payload["authority_contract"]["mcp_governance_exposed"] is False
    assert payload["authority_contract"]["mcp_workspace_mutation_exposed"] is False


def test_platform_api_rejects_governance_and_mutation_before_dispatch(monkeypatch):
    called = False

    def fake_main(argv):
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(platform_api, "release_main", fake_main)
    api = BeforeDeployPlatformAPI()

    with pytest.raises(PermissionError, match="governance"):
        api.execute("approve", [])
    with pytest.raises(PermissionError, match="workspace-mutation"):
        api.execute("regress", [])

    assert called is False


def test_platform_api_explicit_policy_can_enable_governance_and_mutation(monkeypatch):
    calls: list[list[str]] = []

    def fake_main(argv):
        calls.append(argv)
        print("ok")
        return 0

    monkeypatch.setattr(platform_api, "release_main", fake_main)
    api = BeforeDeployPlatformAPI(
        policy=PlatformApiPolicy(
            allow_governance=True,
            allow_workspace_mutation=True,
        )
    )

    approval = api.execute("approve", ["artifact.json"])
    regression = api.execute("regress", ["artifact.json"])

    assert calls == [["approve", "artifact.json"], ["regress", "artifact.json"]]
    assert approval.exit_code == 0
    assert regression.exit_code == 0


def test_platform_api_json_preserves_authoritative_nonzero_release_payload(monkeypatch):
    payload = {
        "status": "BLOCK",
        "gate_effect": "BLOCK",
        "authority": "RELEASE_DISPOSITION",
        "disposition_sha256": "a" * 64,
    }

    def fake_main(argv):
        assert argv == ["release", "report.json", "--format", "json"]
        print(dumps(payload), end="")
        return 1

    monkeypatch.setattr(platform_api, "release_main", fake_main)
    result = BeforeDeployPlatformAPI().execute_json("release", ["report.json"])

    assert result.status == PLATFORM_API_STATUS_COMPLETED
    assert result.exit_code == 1
    assert result.payload == payload
    assert result.stderr == ""


def test_platform_api_json_rejects_format_override(monkeypatch):
    monkeypatch.setattr(platform_api, "release_main", lambda argv: 0)

    with pytest.raises(ValueError, match="owns the --format"):
        BeforeDeployPlatformAPI().execute_json("inspect", ["review.json", "node", "--format", "json"])


def test_platform_api_rejects_unknown_operation_before_dispatch(monkeypatch):
    called = False

    def fake_main(argv):
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(platform_api, "release_main", fake_main)

    with pytest.raises(ValueError, match="Unsupported Platform API operation"):
        BeforeDeployPlatformAPI().execute("shell", ["rm", "-rf", "."])

    assert called is False


def test_platform_api_enforces_capture_limit(monkeypatch):
    def fake_main(argv):
        print("x" * 20, end="")
        return 0

    monkeypatch.setattr(platform_api, "release_main", fake_main)
    api = BeforeDeployPlatformAPI(policy=PlatformApiPolicy(max_capture_chars=10))

    with pytest.raises(ValueError, match="capture limit"):
        api.execute("inspect", ["review.json", "node"])


def test_platform_api_rejects_nul_arguments(monkeypatch):
    monkeypatch.setattr(platform_api, "release_main", lambda argv: 0)

    with pytest.raises(ValueError, match="NUL"):
        BeforeDeployPlatformAPI().execute("inspect", ["bad\x00path"])
