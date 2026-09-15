# Codex thin client

PR39 adds an explicit-use Codex skill for operating Before Deploy without moving any assurance or release authority into Codex.

## Architecture

```text
Codex / optional read-only subagents
        ↓
repo-scoped before-deploy-assure skill
        ↓
installed before-deploy CLI
        ↓
canonical persisted request/evidence contracts
        ↓
deterministic verification/history/release disposition
```

The skill is stored under `.agents/skills/before-deploy-assure`, which is a repository-scoped Codex skill location. `agents/openai.yaml` disables implicit invocation so Codex does not auto-enter a workflow that can eventually reach approval or workspace mutation.

## Delegation is not authority

Delegated agents may help draft bounded advisory responses for investigation, explanation, or remediation proposal requests. Their output remains advisory and must be imported through Before Deploy validation before downstream use.

Delegation cannot supply or infer:

- the human `APPROVE` / `REJECT` choice;
- approver identity;
- exact `proposal_sha256` confirmation;
- exact `patch_sha256` materialization confirmation;
- mutation operator identity;
- final `READY`, `HOLD`, `BLOCK`, or `ERROR` release status.

Agreement among several agents is not a release-authority signal. Canonical correlation/corroboration artifacts remain diagnostic and gate-neutral.

## Approval and mutation

Generic continuation language such as `go`, `continue`, or `proceed` is not proposal approval. The exact proposal digest, explicit decision, and declared approver identity are required by the existing workflow.

Likewise, `regress` materialization requires explicit confirmation of the exact patch digest and declared operator identity. Codex and delegated agents must not apply patch bytes with editing tools or `git apply` to bypass a Before Deploy hash/scope rejection.

## Regression evidence

Regression results must correspond to real executions. Codex may not fabricate PASS status, exit codes, duration, command metadata, or stdout/stderr digests. Missing execution remains missing/incomplete evidence.

## Release boundary

Only `before-deploy release` can emit final release disposition. Codex reports the canonical result unchanged, including limitations and non-ready outcomes.

A `READY` result remains bounded: it means declared deterministic policy, current verification, snapshot, materialization, and configured trust requirements were satisfied for the release scope. It is not a proof of absence of defects or vulnerabilities.

## Exclusions

PR39 adds no MCP server, hook, custom Codex executable, API model call, alternate verifier, automatic mutation, deployment integration, or release-decision implementation. PR40 owns MCP/API exposure.
