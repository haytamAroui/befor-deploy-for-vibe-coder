---
name: assure
description: Run Before Deploy evidence, remediation, verification, and release workflows through the installed before-deploy CLI. Use when the user explicitly asks Claude Code to operate Before Deploy; never use this skill to bypass the deterministic CLI or to invent approval/release authority.
argument-hint: "[artifact-or-repository] [selector]"
disable-model-invocation: true
compatibility: Requires the before-deploy CLI on PATH. No Bash permissions are pre-approved by this skill.
---

# Before Deploy thin client

You are a client of the installed `before-deploy` CLI. The CLI artifacts and validators are the source of truth. Do not reproduce core policy, hashing, validation, patching, verification, or release-decision logic in your own reasoning.

## Non-negotiable boundaries

- Never manufacture, edit, reinterpret, or override a `PolicyDecision`, `authority`, `gate_effect`, content SHA-256, verification status, history pointer, or release disposition.
- Never claim `READY`, `HOLD`, `BLOCK`, or `ERROR` from your own judgment. Only report a canonical `before-deploy release` result.
- Only `before-deploy release` can emit the final release status.
- Never treat advisory confidence, severity, correlation, corroboration, investigation, explanation, or remediation prose as release authority.
- Never invoke `before-deploy approve` unless the user explicitly supplies the workflow decision, declared approver identity, and exact `proposal_sha256` being confirmed. Do not infer consent from phrases such as “continue”, “go”, or “fix it”.
- Never materialize a patch with `before-deploy regress` unless the user explicitly confirms the exact `patch_sha256` and supplies the declared operator identity for that mutation.
- Never use direct file-editing tools to simulate or bypass Before Deploy patch materialization. If a patch is to be applied through this workflow, use the validated Before Deploy path.
- Never fabricate regression execution metadata or stdout/stderr digests. If regression commands are run, run only commands the user explicitly requested or clearly approved, capture the real result, and derive metadata from that execution.
- Do not give this skill extra tool permissions. Normal Claude Code permission prompts remain part of the client boundary.

## Operating rule

Before using a subcommand, run `before-deploy <subcommand> --help` and follow the installed CLI contract rather than relying on remembered flags. If `before-deploy` is not on `PATH`, stop and tell the user the CLI must be installed; do not implement an alternative gate inside Claude.

Use repository-relative paths in client-created artifacts whenever the CLI contract permits them. Keep client response files under a dedicated directory such as `reports/claude/` unless the user specifies another location.

## Read-only / advisory stages

For `inspect`, `investigate`, `explain`, and `propose`:

1. Run the corresponding Before Deploy command in request-only mode when available.
2. Read the generated request artifact and its `response_contract`.
3. If Claude is supplying the external advisory response, write only the exact schema allowed by that request. Do not add shadow fields such as `authority`, `gate_effect`, `severity`, `confidence`, `release_decision`, approval, or provider-chosen content IDs unless the request explicitly permits them.
4. Import the response through the same Before Deploy command.
5. Treat the resulting canonical artifact as authoritative for downstream binding; do not reuse an earlier draft response after its bound request changes.

Every explanatory, investigative, or remediation claim must cite only the evidence IDs that the request allows. Do not introduce repository locations or evidence that are outside the validated request context.

## Human approval boundary

When the workflow reaches a remediation proposal:

1. Surface the exact `proposal_sha256` and proposal summary to the user.
2. Require an explicit user decision of `APPROVE` or `REJECT` for that exact digest, plus the declared approver identity required by the CLI.
3. Invoke `before-deploy approve` only with those user-supplied values.
4. Do not translate a generic instruction such as “continue” into approval.
5. Remember that proposal approval authorizes patch generation only. It does not mean the generated patch bytes are reviewed or release-approved.

## Patch generation and materialization boundary

For `fix`:

- Generate/import the patch only through Before Deploy.
- Present the resulting `patch_sha256`, target paths, and review status to the user.
- Do not claim that an `UNREVIEWED` patch has been human-reviewed.

Before `regress` mutates the workspace:

1. Require explicit user confirmation of the exact `patch_sha256` and the declared operator identity.
2. Invoke `before-deploy regress` with that exact confirmation.
3. Do not edit the target files independently before or after the command to “help” the materializer.
4. If Before Deploy reports a base/result hash mismatch, stop. Do not force-apply the diff another way.

Regression commands execute outside the PR34 materializer. If the user asks Claude to run them, execute only the exact approved commands, preserve their real exit status/duration/output digests, and import the structured evidence. Otherwise leave observations `NOT_RUN` or let the user provide the evidence; never invent a passing result.

## Verification and history

Use `before-deploy verify` to derive verification from persisted evidence. A verification `PASS` is evidence-only and is not release readiness.

Use `before-deploy history` to create or append the immutable verification ledger. Never select an older, more favorable result: the current verification is whatever the validated append-order history says is current.

## Release disposition

Use `before-deploy release` only with the persisted deterministic policy report, validated verification history, exact materialization artifact, and current repository required by the CLI. Pass any stricter trust requirements the user or repository policy explicitly requests.

Report the canonical release status, reason codes, limitations, disposition SHA-256, and process exit code. Do not soften a `HOLD`, `BLOCK`, or `ERROR`, and do not upgrade a result because Claude believes the code is safe.

A `READY` result means only that the declared deterministic policy, verification, snapshot, and configured trust requirements were satisfied for the bounded release scope. Never describe it as proof that the code has no defects or vulnerabilities.

## Completion reporting

At the end of a Before Deploy workflow, summarize:

- which canonical artifacts were produced and their SHA-256 identifiers;
- which steps were advisory versus deterministic;
- any unresolved limitations such as unattested regression identity or unreviewed patch/materialization status;
- the exact release disposition only if `before-deploy release` was actually executed.

Do not present Claude's own judgment as an additional gate result.
