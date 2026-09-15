---
name: before-deploy-assure
description: Explicit-use Codex workflow for operating Before Deploy evidence, remediation, verification, and release commands through the installed before-deploy CLI without granting Codex or delegated agents release authority.
---

# Before Deploy Codex thin client

Use this skill only when the user explicitly invokes `$before-deploy-assure` or otherwise explicitly asks Codex to operate the Before Deploy workflow. The installed `before-deploy` CLI, its persisted request/artifact contracts, and its validators are the source of truth.

Do not reproduce core policy, hashing, evidence validation, patch application, verification, history resolution, or release-decision logic in Codex reasoning or delegated agents.

## Non-negotiable authority boundaries

- Never manufacture, edit, reinterpret, or override a `PolicyDecision`, `authority`, `gate_effect`, content SHA-256, verification status, verification-history pointer, or release disposition.
- Never claim `READY`, `HOLD`, `BLOCK`, or `ERROR` from Codex judgment. Only `before-deploy release` can emit the final release status.
- Never treat model confidence, severity, correlation, corroboration, investigation, explanation, remediation prose, or agreement among agents as release authority.
- Never invoke `before-deploy approve` unless the user explicitly supplies `APPROVE` or `REJECT`, the exact `proposal_sha256`, and the declared approver identity. Generic continuation such as `go`, `continue`, `proceed`, or `fix it` is not approval.
- Never invoke mutating `before-deploy regress` materialization unless the user explicitly confirms the exact `patch_sha256` and supplies the declared operator identity.
- Never use direct editing, `git apply`, patch tools, or a delegated agent to simulate or bypass a Before Deploy materialization rejection or hash mismatch.
- Never fabricate regression status, exit codes, durations, command metadata, or stdout/stderr digests.
- Never reinterpret a valid `HOLD`, `BLOCK`, or `ERROR` as safe to deploy.

## Operating rule

Before invoking a Before Deploy subcommand, run `before-deploy <subcommand> --help` and follow the installed contract instead of remembered flags. If `before-deploy` is unavailable, stop and report that the CLI must be installed. Do not implement a substitute gate in Codex.

Keep Codex-created response files under a dedicated location such as `reports/codex/` unless the user requests another path. Prefer repository-relative paths in client-authored artifacts whenever the CLI contract permits them.

## Advisory request/response stages

For `inspect`, `investigate`, `explain`, and `propose`:

1. Generate or load the canonical Before Deploy request artifact.
2. Read its response contract and allowed evidence identifiers.
3. When Codex drafts an external advisory response, emit only fields permitted by that exact request contract.
4. Re-import the response through the corresponding Before Deploy command before using it downstream.
5. If the request digest changes, discard stale draft responses instead of rebinding them manually.

Do not add shadow policy fields such as `authority`, `gate_effect`, `severity`, `confidence`, `release_decision`, approval, or provider-chosen content IDs unless the canonical request explicitly permits them.

Every investigative, explanatory, and remediation claim must cite only evidence identifiers allowed by the request.

## Delegation boundary

Codex may delegate bounded, read-only advisory drafting to subagents when doing so is useful. Delegated work must obey all of these rules:

- Give the subagent only the persisted request artifact and the minimum bounded context needed for that advisory response.
- Treat every delegated response as untrusted advisory input until the main workflow re-imports it through Before Deploy validation.
- Do not delegate the user's `APPROVE` or `REJECT` decision, approver identity, proposal-hash confirmation, patch-hash confirmation, operator identity, or final release judgment.
- Do not let a delegated agent mutate the release workspace, apply patch bytes, rewrite deterministic artifacts, or run `before-deploy regress` materialization.
- Do not infer stronger confidence or authority because multiple agents produced similar answers. If corroboration is relevant, rely only on the canonical Before Deploy correlation/corroboration artifacts.
- A subagent running in another worktree may analyze evidence, but evidence from that worktree must not be substituted for the exact workspace/snapshot/materialization lineage consumed by `before-deploy release`.

Delegation is a productivity mechanism, not an authority mechanism.

## Human approval boundary

When a remediation proposal exists:

1. Show the exact `proposal_sha256` and a concise proposal summary to the user.
2. Require an explicit `APPROVE` or `REJECT` decision for that exact digest plus the declared approver identity.
3. Invoke `before-deploy approve` only with those user-supplied values.
4. Do not map `go`, `continue`, `proceed`, or similar language to approval.
5. Remember that proposal approval authorizes patch generation only; it does not mean generated patch bytes were human-reviewed or release-approved.

## Patch generation and materialization

For `fix`, generate or import patch artifacts only through Before Deploy. Surface the resulting `patch_sha256`, target paths, and review status. Do not call an `UNREVIEWED` patch reviewed.

Before `regress` mutates the workspace:

1. Require the user's explicit confirmation of the exact `patch_sha256` and declared operator identity.
2. Run the validated Before Deploy materialization path against the intended workspace.
3. If Before Deploy reports a base hash, result hash, path, symlink, or scope mismatch, stop rather than applying the patch another way.

Regression commands themselves run outside the PR34 materializer. If Codex executes them, execute only commands the user explicitly requested or clearly approved, capture the real execution result, and import only real structured evidence. Otherwise preserve `NOT_RUN`/incomplete evidence rather than inventing PASS.

## Verification and history

Use `before-deploy verify` to derive deterministic verification from persisted materialization and regression evidence. Verification `PASS` remains evidence-only and does not mean release readiness.

Use `before-deploy history` to create or append the immutable verification ledger. Never select an older, more favorable result; the current verification is the exact validated append-order successor.

## Release disposition

Use `before-deploy release` only with the persisted deterministic policy report, validated verification history, exact materialization artifact, and current repository required by the installed CLI. Preserve any stricter trust requirements explicitly requested by the user or repository policy.

Report the canonical release status, reason codes, limitations, disposition SHA-256, and process exit code unchanged. A `READY` result means only that the declared policy, verification, snapshot, and configured trust requirements were satisfied for the bounded release scope. It is not proof that the code contains no defects or vulnerabilities.

## Completion report

Summarize the canonical artifacts created, their relevant SHA-256 identifiers, which stages were advisory versus deterministic, any remaining unattested/unreviewed limitations, and the final release disposition only if `before-deploy release` actually ran.

Never add Codex's own safety judgment as an additional gate result.
