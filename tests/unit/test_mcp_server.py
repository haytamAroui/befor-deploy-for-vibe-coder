from __future__ import annotations

from before_deploy import mcp_server
from before_deploy.platform_api import PlatformApiResult


class FakeServer:
    def __init__(self, name: str, *, instructions: str):
        self.name = name
        self.instructions = instructions
        self.tools: dict[str, object] = {}
        self.resources: dict[str, object] = {}
        self.run_calls: list[dict[str, object]] = []

    def tool(self):
        def decorator(function):
            self.tools[function.__name__] = function
            return function

        return decorator

    def resource(self, uri: str, **kwargs):
        def decorator(function):
            self.resources[uri] = function
            return function

        return decorator

    def run(self, **kwargs):
        self.run_calls.append(kwargs)


class RecordingApi:
    def __init__(self):
        self.calls: list[tuple[str, list[str]]] = []

    def capabilities(self):
        return {
            "schema_version": 1,
            "authority_contract": {
                "release_authority_operation": "release",
                "mcp_governance_exposed": False,
                "mcp_workspace_mutation_exposed": False,
            },
        }

    def execute_json(self, operation: str, arguments: list[str]):
        self.calls.append((operation, arguments))
        payload = {"authority": "RELEASE_DISPOSITION", "status": "BLOCK"} if operation == "release" else {"ok": True}
        return PlatformApiResult(
            schema_version=1,
            operation=operation,
            capability="RELEASE_AUTHORITY" if operation == "release" else "DIAGNOSTIC",
            status="COMPLETED",
            exit_code=1 if operation == "release" else 0,
            stdout="canonical-json",
            stderr="",
            payload=payload,
        )


def _server_and_api():
    api = RecordingApi()
    server = mcp_server.build_mcp_server(api=api, server_factory=FakeServer)
    return server, api


def test_mcp_registers_only_bounded_non_governance_tools():
    server, _ = _server_and_api()

    assert server.name == "preflight-mcp"
    assert set(server.tools) == {
        "before_deploy_inspect",
        "before_deploy_investigate",
        "before_deploy_explain",
        "before_deploy_propose",
        "before_deploy_verify",
        "before_deploy_history",
        "before_deploy_release",
    }
    assert "before_deploy_approve" not in server.tools
    assert "before_deploy_fix" not in server.tools
    assert "before_deploy_regress" not in server.tools
    assert "approval" not in " ".join(server.tools).lower()
    assert mcp_server.MCP_CAPABILITIES_RESOURCE in server.resources
    assert "does not expose human approval" in server.instructions
    assert "Only the canonical before-deploy release operation" in server.instructions


def test_mcp_capabilities_resource_preserves_authority_boundary():
    server, _ = _server_and_api()

    payload = server.resources[mcp_server.MCP_CAPABILITIES_RESOURCE]()

    assert payload["authority_contract"]["release_authority_operation"] == "release"
    assert payload["authority_contract"]["mcp_governance_exposed"] is False
    assert payload["authority_contract"]["mcp_workspace_mutation_exposed"] is False


def test_mcp_inspect_dispatches_typed_json_operation():
    server, api = _server_and_api()

    result = server.tools["before_deploy_inspect"](
        "reports/review.json",
        "advisory-finding:abc",
        "reports/mcp/inspect-one",
    )

    assert api.calls == [
        (
            "inspect",
            [
                "reports/review.json",
                "advisory-finding:abc",
                "--output-dir",
                "reports/mcp/inspect-one",
            ],
        )
    ]
    assert result["payload"] == {"ok": True}
    assert "stdout" not in result


def test_mcp_release_reports_canonical_nonready_result_without_reinterpretation():
    server, api = _server_and_api()

    result = server.tools["before_deploy_release"](
        "reports/report.json",
        "reports/history/verification-history.json",
        "reports/regress/patch-materialization.json",
        ".",
        True,
        True,
        True,
        "reports/mcp/release-one",
    )

    operation, arguments = api.calls[-1]
    assert operation == "release"
    assert "--require-attested-evidence" in arguments
    assert "--require-reviewed-patch" in arguments
    assert "--require-reviewed-materialization" in arguments
    assert result["exit_code"] == 1
    assert result["payload"] == {
        "authority": "RELEASE_DISPOSITION",
        "status": "BLOCK",
    }


def test_mcp_propose_never_infers_or_supplies_approval():
    server, api = _server_and_api()

    server.tools["before_deploy_propose"](
        "reports/review.json",
        "ADV-1",
        "reports/explain/explanation-response.json",
        None,
        None,
        "reports/mcp/propose-one",
    )

    operation, arguments = api.calls[-1]
    assert operation == "propose"
    joined = " ".join(arguments)
    assert "--decision" not in arguments
    assert "--approver" not in arguments
    assert "--confirm-proposal-sha256" not in arguments
    assert "approve" not in joined.lower()


def test_mcp_main_runs_stdio_only(monkeypatch):
    server = FakeServer("preflight-mcp", instructions="test")
    monkeypatch.setattr(mcp_server, "build_mcp_server", lambda: server)

    assert mcp_server.main() == 0
    assert server.run_calls == [{"transport": "stdio"}]
