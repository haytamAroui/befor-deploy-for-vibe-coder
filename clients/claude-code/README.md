# Before Deploy Claude Code client

This directory is a thin Claude Code plugin over the installed `before-deploy` CLI.

It does not contain a second policy engine, patch engine, verifier, or release decision implementation. The plugin contributes one manual-only skill, `/before-deploy:assure`, whose job is to orchestrate the existing CLI contracts and preserve their evidence/authority boundaries.

## Requirements

- Claude Code with plugin/skill support.
- The `before-deploy` executable available on `PATH` in the project where Claude Code is running.
- The Before Deploy artifacts required by the workflow stage you want to use.

The plugin intentionally grants no `allowed-tools` permissions. Normal Claude Code permission prompts still apply.

## Install from this repository marketplace

Add the repository as a marketplace and install the plugin:

```text
/plugin marketplace add haytamAroui/befor-deploy-for-vibe-coder
/plugin install before-deploy@before-deploy-tools
/reload-plugins
```

Then invoke the workflow explicitly:

```text
/before-deploy:assure
```

The plugin manifest omits an explicit version so a git-hosted marketplace install can follow the resolved source commit rather than requiring a manual plugin-version bump for every repository commit.

## Local development

Run Claude Code with the plugin directory directly:

```bash
claude --plugin-dir ./clients/claude-code
```

Validate the marketplace and the plugin while developing:

```bash
claude plugin validate .
claude plugin validate ./clients/claude-code --strict
```

## Safety boundary

The skill is `disable-model-invocation: true`. Claude cannot decide on its own to start this workflow through the Skill tool.

Within the skill:

- advisory request/response stages remain advisory;
- explicit proposal approval requires a user-supplied `APPROVE` or `REJECT`, approver declaration, and exact `proposal_sha256`;
- controlled patch materialization requires a user-confirmed exact `patch_sha256` and declared operator identity;
- regression results must come from real execution metadata or remain not-run/incomplete;
- verification and verification history are consumed as deterministic evidence;
- only `before-deploy release` may produce `READY`, `HOLD`, `BLOCK`, or `ERROR` release disposition.

The plugin must not use direct file editing to bypass the Before Deploy remediation/materialization path.

## What this plugin deliberately does not include

PR38 does not add Claude API calls, model selection, hooks, MCP servers, subagents, background automation, automatic deployment, or any new release-authority logic. Those would either duplicate the core or expand the trust surface beyond a thin client.
