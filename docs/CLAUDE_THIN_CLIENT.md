# Claude thin client

PR38 adds a Claude Code integration without adding another assurance engine.

## Architecture

```text
Claude Code
   |
   | manual /before-deploy:assure skill
   v
before-deploy CLI
   |
   +-- advisory request/response contracts
   +-- evidence graph / inspect / investigate / explain / propose
   +-- explicit human approval workflow
   +-- controlled patch materialization
   +-- regression evidence / verification / history
   `-- deterministic release disposition
```

Claude is a client of these contracts. It is not a release authority and it does not get an alternate API that can bypass them.

## Distribution shape

The repository now contains:

```text
.claude-plugin/marketplace.json
clients/claude-code/
  .claude-plugin/plugin.json
  skills/
    assure/
      SKILL.md
```

The marketplace points at the plugin by repository-relative path. The plugin uses Claude Code's standard `skills/<name>/SKILL.md` layout.

No explicit plugin version is set in PR38. For the git-hosted marketplace path this lets the source commit provide the update identity rather than requiring a manually synchronized version number during active development.

## Invocation control

The `assure` skill sets:

```text
disable-model-invocation: true
```

This is intentional because the workflow can eventually reach user-governed approval and workspace mutation. A user must invoke the skill explicitly; Claude should not decide on its own that a repository should enter the remediation/release workflow.

The skill does not set `allowed-tools`. It therefore grants itself no extra Bash, write, or edit permission. The user's normal Claude Code permission settings still apply.

## Core authority invariant

The plugin may help produce advisory response files for request contracts, but every such response must be imported and validated by the corresponding Before Deploy command before it can become a downstream artifact.

The client may not manufacture or overwrite:

- deterministic `PolicyDecision`;
- authority or `gate_effect` fields;
- content-addressed IDs or SHA-256 bindings;
- verification status or verification-history current pointers;
- release disposition.

Only `before-deploy release` can emit the final release status.

## Human approval invariant

Generic continuation language is not approval.

The Claude client may invoke `before-deploy approve` only after the user explicitly supplies:

```text
APPROVE | REJECT
exact proposal_sha256
declared approver identity
```

Proposal approval authorizes patch generation only. It does not imply review of the generated patch bytes.

## Workspace mutation invariant

The Claude client may invoke the mutating `before-deploy regress` materialization stage only after the user explicitly supplies:

```text
exact patch_sha256
declared operator identity
```

The client must not use Claude's normal editing tools to force-apply a patch that Before Deploy rejected. Base-hash mismatch, result-hash mismatch, scope mismatch, or symlink/path validation failure is a stop condition.

## Regression evidence

PR38 does not turn Before Deploy into an arbitrary command runner.

If a user asks Claude to execute regression commands, Claude may run only the explicitly requested or clearly approved commands under normal Claude Code permissions, then provide the real structured metadata expected by the PR34 response contract. It must not fabricate exit codes, durations, or stdout/stderr hashes.

If no regression execution is authorized, the client must not invent `PASS` evidence.

## Release reporting

The client reports the canonical PR37 result unchanged:

```text
READY | HOLD | BLOCK | ERROR
```

It may explain reason codes and limitations but cannot soften a non-ready disposition or add an independent model opinion that acts like a second gate.

`READY` remains scoped: declared deterministic policy, verification, current snapshot, and configured trust requirements were satisfied for the bounded inputs. It is not a proof of absence of all vulnerabilities.

## Deliberate exclusions

PR38 does not add:

- direct Anthropic API/model calls;
- model configuration or model attestation;
- hooks that automatically run Before Deploy;
- MCP servers;
- Claude subagents;
- auto-approval or auto-materialization;
- deployment actions;
- duplicated policy, hashing, verification, or release logic.

PR39 can add a Codex/delegation client against the same core contracts. PR40 can expose MCP/API surfaces without changing the authority model.
