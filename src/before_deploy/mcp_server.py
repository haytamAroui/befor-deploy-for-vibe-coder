"""Bounded MCP stdio adapter over the transport-neutral Before Deploy platform API."""

from __future__ import annotations

import sys
from typing import Any, Callable

from before_deploy.platform_api import (
    BeforeDeployPlatformAPI,
    PlatformApiResult,
)

MCP_SERVER_NAME = "before-deploy"
MCP_CAPABILITIES_RESOURCE = "before-deploy://capabilities"
MCP_SDK_REQUIREMENT = "mcp>=2,<3"

MCP_INSTRUCTIONS = (
    "Before Deploy exposes validated evidence workflows and deterministic release disposition. "
    "This server does not expose human approval, patch generation, or workspace materialization. "
    "Only the canonical before-deploy release operation may emit final READY/HOLD/BLOCK/ERROR."
)


def build_mcp_server(
    *,
    api: BeforeDeployPlatformAPI | None = None,
    server_factory: Callable[..., Any] | None = None,
) -> Any:
    """Build the MCP server; the SDK import stays optional for the core package."""
    if server_factory is None:
        try:
            from mcp.server import MCPServer
        except (ImportError, ModuleNotFoundError) as error:
            raise RuntimeError(
                f"Before Deploy MCP requires the optional {MCP_SDK_REQUIREMENT!r} package"
            ) from error
        server_factory = MCPServer

    platform = api or BeforeDeployPlatformAPI()
    server = server_factory(MCP_SERVER_NAME, instructions=MCP_INSTRUCTIONS)

    @server.resource(
        MCP_CAPABILITIES_RESOURCE,
        name="before-deploy-capabilities",
        description="Before Deploy transport capabilities and authority boundaries.",
    )
    def before_deploy_capabilities() -> dict[str, Any]:
        return platform.capabilities()

    @server.tool()
    def before_deploy_inspect(
        review_json: str,
        selector: str,
        output_dir: str = "reports/mcp/inspect",
    ) -> dict[str, Any]:
        """Inspect one persisted finding and its validated evidence lineage."""
        return _tool_result(
            platform.execute_json(
                "inspect",
                [review_json, selector, "--output-dir", output_dir],
            )
        )

    @server.tool()
    def before_deploy_investigate(
        review_json: str,
        selector: str,
        response_file: str | None = None,
        output_dir: str = "reports/mcp/investigate",
    ) -> dict[str, Any]:
        """Build bounded investigation context and optionally import an existing response file."""
        arguments = [review_json, selector, "--output-dir", output_dir]
        _append_optional(arguments, "--response-file", response_file)
        return _tool_result(platform.execute_json("investigate", arguments))

    @server.tool()
    def before_deploy_explain(
        review_json: str,
        selector: str,
        response_file: str | None = None,
        investigation_response_file: str | None = None,
        output_dir: str = "reports/mcp/explain",
    ) -> dict[str, Any]:
        """Build cited explanation context and optionally import an existing response file."""
        arguments = [review_json, selector, "--output-dir", output_dir]
        _append_optional(
            arguments,
            "--investigation-response-file",
            investigation_response_file,
        )
        _append_optional(arguments, "--response-file", response_file)
        return _tool_result(platform.execute_json("explain", arguments))

    @server.tool()
    def before_deploy_propose(
        review_json: str,
        selector: str,
        explanation_response_file: str,
        response_file: str | None = None,
        investigation_response_file: str | None = None,
        output_dir: str = "reports/mcp/propose",
    ) -> dict[str, Any]:
        """Build/import a cited non-executable remediation proposal; never approve it."""
        arguments = [
            review_json,
            selector,
            "--explanation-response-file",
            explanation_response_file,
            "--output-dir",
            output_dir,
        ]
        _append_optional(
            arguments,
            "--investigation-response-file",
            investigation_response_file,
        )
        _append_optional(arguments, "--response-file", response_file)
        return _tool_result(platform.execute_json("propose", arguments))

    @server.tool()
    def before_deploy_verify(
        review_json: str,
        selector: str,
        explanation_response_file: str,
        proposal_response_file: str,
        approval_file: str,
        patch_response_file: str,
        materialization_authorization_file: str,
        materialization_file: str,
        regression_evidence_file: str,
        investigation_response_file: str | None = None,
        output_dir: str = "reports/mcp/verify",
    ) -> dict[str, Any]:
        """Deterministically verify already-persisted regression evidence without mutation."""
        arguments = [
            review_json,
            selector,
            "--explanation-response-file",
            explanation_response_file,
            "--proposal-response-file",
            proposal_response_file,
            "--approval-file",
            approval_file,
            "--patch-response-file",
            patch_response_file,
            "--materialization-authorization-file",
            materialization_authorization_file,
            "--materialization-file",
            materialization_file,
            "--regression-evidence-file",
            regression_evidence_file,
            "--output-dir",
            output_dir,
        ]
        _append_optional(
            arguments,
            "--investigation-response-file",
            investigation_response_file,
        )
        return _tool_result(platform.execute_json("verify", arguments))

    @server.tool()
    def before_deploy_history(
        verification_json: str,
        history_file: str | None = None,
        output_dir: str = "reports/mcp/history",
    ) -> dict[str, Any]:
        """Create or append immutable verification history from canonical verification evidence."""
        arguments = [verification_json, "--output-dir", output_dir]
        _append_optional(arguments, "--history-file", history_file)
        return _tool_result(platform.execute_json("history", arguments))

    @server.tool()
    def before_deploy_release(
        policy_report_json: str,
        verification_history_file: str,
        materialization_file: str,
        repository: str,
        require_attested_evidence: bool = False,
        require_reviewed_patch: bool = False,
        require_reviewed_materialization: bool = False,
        output_dir: str = "reports/mcp/release",
    ) -> dict[str, Any]:
        """Compute the canonical deterministic release disposition; never reinterpret it."""
        arguments = [
            policy_report_json,
            "--verification-history-file",
            verification_history_file,
            "--materialization-file",
            materialization_file,
            "--repository",
            repository,
            "--output-dir",
            output_dir,
        ]
        _append_flag(arguments, "--require-attested-evidence", require_attested_evidence)
        _append_flag(arguments, "--require-reviewed-patch", require_reviewed_patch)
        _append_flag(
            arguments,
            "--require-reviewed-materialization",
            require_reviewed_materialization,
        )
        return _tool_result(platform.execute_json("release", arguments))

    return server


def main() -> int:
    """Run the bounded MCP surface over stdio only."""
    try:
        server = build_mcp_server()
    except RuntimeError as error:
        print(f"before-deploy-mcp: ERROR: {error}", file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0


def _tool_result(result: PlatformApiResult) -> dict[str, Any]:
    value = {
        "schema_version": result.schema_version,
        "operation": result.operation,
        "capability": result.capability,
        "status": result.status,
        "exit_code": result.exit_code,
        "stderr": result.stderr,
        "payload": result.payload,
    }
    if result.payload is None:
        value["stdout"] = result.stdout
    return value


def _append_optional(arguments: list[str], flag: str, value: str | None) -> None:
    if value is not None:
        arguments.extend([flag, value])


def _append_flag(arguments: list[str], flag: str, enabled: bool) -> None:
    if enabled:
        arguments.append(flag)


if __name__ == "__main__":
    raise SystemExit(main())
