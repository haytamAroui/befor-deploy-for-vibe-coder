# Next.js Server Action and Proxy Boundary

**Status:** Implemented as a narrow static control. This document describes observable source patterns only; it does not certify authentication, authorization, ownership checks, middleware/proxy coverage, runtime route behavior, or application security.

## Purpose

`SEC-NEXT-ACTION-001` checks a specific structural condition in a detected Next.js repository: a named exported `async function` inside a module whose first statement is `'use server'` or `"use server"`, containing a direct `db` or `prisma` mutation before any recognized local guard-marker call. The control reports the action name and mutation category, but never source excerpts, argument values, database identifiers, import paths, request data, or credential material.

Next.js documents exported Server Actions as direct POST entry points and requires authentication and authorization to be re-verified inside every action. A page-level check does not extend to the action.[1] The control expresses that review expectation as a deliberately constrained finding pattern; it does not prove whether an actual guard succeeds or whether a resource-specific authorization check is correct.

> **`middleware` and `proxy` do not suppress this finding.** The control records their root or `src/` convention presence only as execution metadata. Next.js explicitly warns that a Proxy matcher can skip Server Function calls and that every Server Function must verify authentication and authorization rather than rely on Proxy coverage.[2]

## Detection contract

| Observable fact | Handling |
|---|---|
| Detected Next.js project | The control is compatible and runs when a selected policy includes `SEC-NEXT-ACTION-001`. |
| Module-level `use server` directive | The source file enters the narrow Server Action scope. Directives inside a function body are excluded. |
| Named `export async function` | The function is considered. Default exports, arrow functions, aliases, and closures are excluded. |
| Direct `db` or `prisma` create, delete, update, or upsert call | The function has a bounded ORM mutation marker. Reads, raw-query methods, and unfamiliar client shapes are excluded. |
| Recognized local guard marker before the mutation | No finding is emitted for that narrow pattern. The marker is **not proof** of a real guard. |
| Root or `src/` `middleware.*` / `proxy.*` file | Recorded as `middleware`, `proxy`, `middleware+proxy`, or `absent`; never treated as a protection result. |

The marker set is intentionally finite: `auth`, `authorize`, `requireUser`, `requireAdmin`, `requireRole`, `requirePermission`, `requireOwnership`, `assertUser`, `assertAdmin`, `assertRole`, `assertPermission`, `assertOwnership`, `verifyUser`, `verifyAdmin`, `verifyRole`, `verifyPermission`, and `verifyOwnership`. The marker must appear as a direct local call before the matched mutation in the same function body.

## Explicit exclusions

| Excluded area | Why no conclusion is made |
|---|---|
| Authentication, authorization, role, tenant, and ownership correctness | Static name matching cannot establish semantics, identity binding, policy correctness, or resource-level permission. |
| Middleware/proxy matcher coverage | Next.js matcher behavior is route- and deployment-dependent; a matcher can exclude Server Function calls.[2] |
| Imported data-access delegates and custom clients | Following imports, aliases, wrappers, or ORM configuration would require broader semantic/dataflow analysis. |
| Inline actions, arrow functions, default exports, and closures | The first contract chooses named exported module-level functions to keep its matching and false-positive boundary reviewable. |
| Client validation, CSRF, returned data, server-only imports, rate limiting, and runtime configuration | These require distinct contracts and fixtures. Next.js recommends action-level validation and authorization, but this rule does not infer them.[1] |
| A clean result | It means only that the precise pattern was not found. It never means that Server Actions are protected or that no action exists. |

## Policy and authority

The control is selected in the native default, strict CI, strict release, release-evidence, and external-adapter profiles. It remains non-applicable outside detected Next.js projects. Findings are normalized before the existing deterministic policy engine assigns their configured disposition; neither the control, capability manifest, domain catalog, plan, coverage audit, nor proxy metadata can decide a release outcome.

The paired non-executable contract is `CONTROL-AUTHORIZATION-NEXT-SERVER-ACTION-001`, mapped only to `DOMAIN-AUTHORIZATION-001`. The catalog mapping describes coverage scope. It does not create a universal Next.js or authorization claim.

## Fixture matrix

The test matrix contains an unguarded direct mutation, a direct mutation with a preceding local guard marker, a proxy-only case, comments/strings plus inline-action ambiguity, and a non-Next.js repository. The proxy-only fixture still produces the Server Action finding, demonstrating that proxy presence cannot become an implicit waiver.

## References

[1]: https://nextjs.org/docs/app/guides/data-security "Next.js Data Security — Server Actions, action-level authentication and authorization"
[2]: https://nextjs.org/docs/app/api-reference/file-conventions/proxy "Next.js Proxy convention, matcher behavior, and Server Function boundary"
[3]: https://nextjs.org/docs/app/guides/authentication "Next.js Authentication guide — server-side validation and authorization"
