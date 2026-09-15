# Before Deploy for Codex

This directory documents the Codex thin-client workflow shipped by Before Deploy.

The actual repo-scoped Codex skill lives at:

```text
.agents/skills/before-deploy-assure/
```

Codex discovers repository skills from `.agents/skills` between the current working directory and repository root. The included `agents/openai.yaml` sets `allow_implicit_invocation: false`, so the workflow is explicit-use only.

Invoke it from Codex with:

```text
$before-deploy-assure
```

The skill is orchestration guidance only. It does not contain policy, hashing, verification, patch-application, history-resolution, or release-decision code. The installed `before-deploy` CLI remains the implementation and source of truth.

## Delegation

Codex may delegate bounded read-only advisory drafting to subagents, but delegated results remain untrusted until re-imported through Before Deploy. Human approval, exact proposal/patch digest confirmations, workspace mutation, and final release disposition are not delegable authority.

## Installation outside this repository

For personal use in another repository, install/copy the `before-deploy-assure` skill into your user skill directory (`$HOME/.agents/skills`) or use Codex's skill installer to install it from this repository. Restart Codex only if discovery does not refresh automatically.

The `before-deploy` executable must still be installed and available on `PATH`.

## Deliberate exclusions

This client adds no MCP server, Codex configuration override, hooks, background automation, model API integration, auto-approval, auto-materialization, deployment action, or alternate release authority.
