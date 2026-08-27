# Bounded Next.js Inline Server Action Contract

**Status:** Implemented as a deliberately narrow native static control. This document describes one lexical action shape only; it does not establish that an application is authorized, secure, reachable, production-ready, or compliant.

## Purpose and authority boundary

`SEC-NEXT-INLINE-ACTION-001` inspects one named nested `async function` form with an inline `'use server'` or `"use server"` directive. Next.js documents that `use server` may appear at the top of a function to designate a Server Function.[1] It also advises that Server Actions should be treated as direct POST entry points and re-verify authentication and authorization inside each action rather than relying on page-level checks.[2]

> **Only the versioned deterministic policy engine is a release authority.** This control produces normalized evidence only. A local guard marker, a green result, page-level check, `middleware`, or `proxy` convention cannot approve a release or prove authorization.

The control is selected only by `rules/nextjs-inline-server-actions-policy.yaml`. The default, strict, and CI policy profiles do not implicitly select it. The existing `SEC-NEXT-ACTION-001` remains separate and covers only named exported async functions in module-level `use server` files.

## Exact recognized shape

A finding requires all of the following conditions in an inventory-included JavaScript or TypeScript source file of a detected Next.js repository.

| Condition | Static rule |
|---|---|
| Function form | A named `async function name(...) { ... }` declaration nested in a lexical block. |
| Server directive | The inline `use server` directive is the first executable statement in that function body; leading comments are ignored. |
| Mutation form | A direct `db` or `prisma` chain ends in `create`, `createMany`, `delete`, `deleteMany`, `update`, `updateMany`, or `upsert`. |
| Guard review heuristic | No reviewed local guard-marker call occurs before that direct mutation within the same action body. |
| Finding identity | Action name, mutation category, source-relative path, and positive line only. |

The implementation blanks comments and string literals before its lexical matching and uses a bounded balanced-block walk. It retains neither function arguments, source excerpts, database model names, import paths, request data, credentials, upstream documentation text, nor raw source.

## Deliberate exclusions

The control does **not** recognize arrow-function actions, JSX `action={async () => ...}` callbacks, exported/module-level actions, non-async functions, directives after executable statements, aliases, wrappers, imports, arbitrary ORM instances, indirect mutations, or custom mutation names. These are explicit unsupported shapes, not clean results.

A recognized guard marker such as `auth()`, `authorize()`, or `requireUser()` is only a local lexical signal. It does not verify the guard implementation, user identity, role, permission, ownership, tenant isolation, input validation, data-access-layer behavior, return-value filtering, closures, route reachability, or runtime behavior. Page-level checks and `middleware`/`proxy` convention metadata are never accepted as action-local authorization evidence.[2]

## Policy and reporting behavior

A finding has rule ID `SEC-NEXT-INLINE-ACTION-001`, version `0.1.0`, high severity, and medium confidence. The dedicated policy currently assigns it `BLOCK`; that disposition is a policy choice and not an inherent finding property. A policy may instead require an exact, expiry-bound waiver according to the existing waiver contract.

Completed execution metadata may record the root or `src/` proxy/middleware convention as a structural fact. This metadata is not a finding, coverage state, guard, waiver target, or policy input. If Next.js is not detected, the control is explicitly `NOT_APPLICABLE`.

## Calibration matrix

| Fixture class | Expected behavior |
|---|---|
| Named nested inline action with direct mutation and no local marker | One normalized finding. |
| Same named inline form with a preceding local marker | No finding from this control; this is not authorization proof. |
| Page-level guard with unguarded named inline action | One finding; page checks are not action checks. |
| Arrow action, module-level/exported action, or directive after executable code | No finding from this control because the shape is excluded. |
| Non-Next.js repository | `NOT_APPLICABLE`. |

## References

[1]: https://nextjs.org/docs/app/api-reference/directives/use-server "Next.js use server directive"
[2]: https://nextjs.org/docs/app/guides/data-security "Next.js data security and Server Action guidance"
