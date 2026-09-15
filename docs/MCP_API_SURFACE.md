# Before Deploy MCP / Platform API Surface

PR40 exposes the established Before Deploy contracts to programmatic clients without adding another policy engine or another release authority.

The architecture is intentionally two layers:

```text
client / MCP host
      |
      v
BeforeDeployPlatformAPI
      |
      v
existing before-deploy entrypoint chain
      |
      +-- evidence/advisory artifacts (gate-neutral)
      +-- deterministic verification/history
      `-- release disposition (sole final release authority)
```

The platform API does not reimplement scanning, evidence validation, patching, verification, history resolution, or release logic. It invokes the same installed command dispatcher in-process and captures its canonical output and exit code.

## Platform API

`before_deploy.platform_api.BeforeDeployPlatformAPI` is transport-neutral.

Each operation is assigned a fixed capability class:

- `scan` -> `DETERMINISTIC_GATE`
- `review` -> `ADVISORY_REVIEW`
- `benchmark` / `inspect` -> `DIAGNOSTIC`
- `investigate` / `explain` / `propose` -> `ADVISORY_WORKFLOW`
- `approve` -> `HUMAN_GOVERNANCE`
- `fix` -> `PATCH_GENERATION`
- `regress` -> `WORKSPACE_MUTATION`
- `verify` / `history` -> `DETERMINISTIC_EVIDENCE`
- `release` -> `RELEASE_AUTHORITY`

The default `PlatformApiPolicy` disables `approve`, `fix`, and `regress`. A trusted non-MCP embedding can explicitly enable governance and/or workspace mutation, but doing so does not change any underlying approval, digest, scope, or authority validation.

Example:

```python
from before_deploy.platform_api import BeforeDeployPlatformAPI

api = BeforeDeployPlatformAPI()
result = api.execute_json(
    "inspect",
    ["reports/review.json", "advisory-finding:..."],
)
```

`execute_json()` owns `--format json` and parses only the canonical stdout emitted by the existing command. A non-zero process exit is not automatically a transport failure: for example, `before-deploy release` intentionally returns non-zero for canonical `HOLD`, `BLOCK`, or authoritative `ERROR` results. When canonical JSON is present, the API preserves that payload unchanged.

The API envelope is transport metadata only. It does not carry a competing `authority` or `gate_effect` field.

## MCP server

`preflight-mcp` (aliased as `before-deploy-mcp`) is a thin stdio server adapter. It uses the current official Model Context Protocol Python SDK v2 API (`MCPServer`) when that SDK is present in the runtime environment.

The core Preflight package deliberately does not depend on MCP. Install the SDK in the same environment when using the MCP adapter, for example:

```text
pip install "mcp>=2,<3"
preflight-mcp
```

or run directly from GitHub without cloning:

```text
uvx --from git+https://github.com/haytamAroui/preflight.git --with "mcp>=2,<3" preflight-mcp
```

or during repository development:

```text
uv run --with "mcp>=2,<3" preflight-mcp
```

PR40 exposes stdio only. Network transports, authentication, remote multi-tenant execution, and hosted deployment are outside this increment.

### MCP resource

```text
before-deploy://capabilities
```

returns the platform operation classes, default enablement, and the explicit authority boundary.

### MCP tools

The default server registers exactly:

```text
before_deploy_inspect
before_deploy_investigate
before_deploy_explain
before_deploy_propose
before_deploy_verify
before_deploy_history
before_deploy_release
```

The advisory tools accept existing response-file paths when the corresponding CLI contract supports importing a response. They never generate an approval decision or infer human consent.

The deterministic tools consume already-persisted canonical evidence. `before_deploy_verify` does not apply a patch or run regression commands. `before_deploy_release` returns the canonical release artifact and exit code without reinterpreting either.

## Deliberately absent MCP tools

The MCP server does **not** register:

```text
approve
fix
regress
```

This is a structural boundary rather than an instruction-only boundary.

An MCP-connected model therefore cannot use this server to:

- assert a human `APPROVE` / `REJECT` decision;
- provide an approver identity as though it were the user;
- confirm a proposal digest on the user's behalf;
- generate a patch through the approval-gated `fix` path;
- confirm a patch digest for mutation;
- materialize a patch into the release workspace;
- fabricate regression execution evidence.

Those workflows remain explicit CLI / trusted-embedding operations with the PR33/PR34 confirmation contracts.

## Release authority

MCP does not create a new release authority.

```text
advisory MCP tools
      -> gate_effect = NONE in their canonical artifacts

verify/history
      -> deterministic evidence, not release readiness

before_deploy_release
      -> existing RELEASE_DISPOSITION authority
```

Only the canonical `before-deploy release` implementation can emit final `READY`, `HOLD`, `BLOCK`, or `ERROR`. The MCP adapter merely transports that result.

Provider confidence, multi-agent agreement, advisory severity, correlation, corroboration, investigation, explanation, and remediation prose remain outside the release decision.

## Security notes

- No generic `argv` MCP tool is exposed.
- No shell-command MCP tool is exposed.
- No direct file-edit or patch-apply MCP tool is exposed.
- No MCP tool can opt itself into `PlatformApiPolicy.allow_governance` or `allow_workspace_mutation`.
- Tool arguments are passed through the same canonical CLI validators and artifact loaders.
- NUL-containing API arguments are rejected.
- Captured stdout/stderr is bounded by the platform policy.
- The MCP server is stdio-only in PR40, avoiding an unauthenticated listening socket by default.

The transport boundary does not turn SHA-256 content identifiers into signatures or attest identities that the underlying evidence marks as untrusted/unattested.

## Scope after PR40

PR40 completes the initial platform roadmap through external client surfaces. Future work can add authenticated HTTP deployment, richer SDK bindings, session persistence, and organization policy around MCP tool exposure, but those should remain adapters over the same deterministic authority model rather than new release engines.
