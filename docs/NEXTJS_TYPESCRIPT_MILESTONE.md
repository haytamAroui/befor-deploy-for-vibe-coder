# Next.js and TypeScript Control Milestone

**Status:** Implemented bounded Next.js/TypeScript control set
**Purpose:** Add narrow, deterministic checks that close meaningful coverage gaps for visible Next.js/TypeScript code without representing syntax matching as full semantic analysis.

## Evidence basis

Next.js documents that any environment variable prefixed `NEXT_PUBLIC_` is inlined into JavaScript delivered to the browser at build time. It should therefore never be used for a value named as a secret, private credential, database connection, or session/authentication token. [1]

Next.js also recommends `httpOnly`, `secure`, and `sameSite` options for session cookies; it explains that `httpOnly` prevents client-side JavaScript access and `secure` confines transmission to HTTPS. [2] Its documented headers configuration allows static CORS response headers, including `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. [3]

> **Control boundary:** The controls below inspect only a bounded working tree. They do not run `next build`, evaluate JavaScript/TypeScript, resolve computed object values, determine whether a named value is truly secret, prove authorization, or determine effective runtime headers behind a proxy/CDN.

## Controls

| Control ID | Trigger | Finding condition | Initial disposition | Deliberate exclusions |
|---|---|---|---|---|
| `SEC-NEXT-ENV-001` | Detected Next.js project; JS/TS source | Direct `process.env.NEXT_PUBLIC_*` access where the variable name contains `SECRET`, `PASSWORD`, `PRIVATE`, `DATABASE_URL`, `ACCESS_TOKEN`, `AUTH_TOKEN`, `SESSION_TOKEN`, or `API_SECRET`. | `BLOCK` | Generic `KEY`, analytics identifiers, public application IDs, computed property access, and non-Next public settings are not flagged. |
| `SEC-NEXT-COOKIE-001` | Detected Next.js project; JS/TS source | A direct `cookies().set(...)` / `cookieStore.set(...)` call for a statically named session/auth/token cookie explicitly sets `httpOnly: false`, `secure: false`, or combines `sameSite: 'none'` with `secure: false`. | `BLOCK` | Missing/indirect options, non-session cookies, computed names/options, and custom cookie wrappers are not inferred. |
| `SEC-NEXT-CORS-001` | Detected Next.js project; `next.config.*` | The same static header object visibly declares `Access-Control-Allow-Origin: '*'` and `Access-Control-Allow-Credentials: 'true'`. | `BLOCK` | Dynamic headers, route-handler CORS logic, middleware, reverse proxies, and wildcard origin without credentials are not evaluated. |
| `SEC-NEXT-ACTION-001` | Detected Next.js project; named exported async function in a module-level `use server` file | A direct `db`/`prisma` mutation appears before any finite recognized local authorization-marker call. Root or `src/` `middleware.*` / `proxy.*` presence is recorded only as metadata. | `BLOCK` | A marker does not prove authorization or ownership; imported delegates, aliases, closures, matchers, proxy/middleware coverage, dataflow, and runtime conditions are not inferred. Named inline actions belong only to the separate contract. [4] [5] |
| `SEC-NEXT-INLINE-ACTION-001` | Detected Next.js project; named nested async function with inline `use server` as its first executable statement | A direct `db`/`prisma` mutation appears before any finite recognized local authorization-marker call in the same action body. | `BLOCK` in its dedicated opt-in profile | A marker does not prove authorization or ownership; arrow actions, module-level/exported actions, directives after executable code, imported delegates, aliases, closures, page checks, proxy/middleware, dataflow, and runtime conditions are not inferred. [4] [5] |

## Applicability and decision semantics

The adaptive capability catalog marks all five controls as requiring the **Next.js** framework signal. A policy may select them for every repository; a non-Next repository receives explicit `NOT_APPLICABLE` executions rather than silent omission. A Next.js project without one of the risky patterns receives a completed execution with zero findings.

Each finding has a stable fingerprint, redacted evidence consisting only of path, line, and variable/cookie/header identifiers, and ordinary policy handling. The project profile never decides `PASS` or suppresses a finding.

## Test matrix

| Fixture | Expected result |
|---|---|
| Secure Next.js fixture | `PASS`; static public analytics ID, secure session cookie options, and specific/credentialed CORS configuration are accepted. |
| Vulnerable Next.js fixture | `BLOCK`; exposes a named public secret, writes a session cookie with explicitly unsafe options, and uses wildcard origin plus credentials. |
| Python/FastAPI fixture | All five controls are `NOT_APPLICABLE`; existing Python controls retain their previous behavior. |
| Unguarded module-level Server Action fixture | `BLOCK`; a named exported action directly deletes through Prisma with no preceding local guard marker. |
| Local-guard fixture | `PASS`; a recognized local guard marker precedes the direct mutation. This is not treated as semantic authorization proof. |
| Proxy-only fixture | `BLOCK`; proxy presence is reported as a structural fact but does not suppress the action finding. |
| Named inline Server Action fixture | The dedicated inline profile blocks an unguarded direct mutation; default policy does not select this separate control. |
| Local inline marker fixture | No inline finding when a recognized local marker precedes the direct mutation; this is not semantic authorization proof. |
| Page-only guard fixture | The dedicated inline profile blocks; page-level checks do not guard an action entry point. |
| Arrow/module-level/directive-late ambiguity fixture | No inline finding; these forms are outside the separate inline contract. |
| Dynamic/unknown constructs | No speculative finding. The report retains the static-analysis boundary in its limitations. |

## Deferred controls

Semantic Server Actions authorization and ownership, client/server data-boundary analysis, dynamic route handlers, middleware/proxy authorization, arrow and closure actions, imported delegate analysis, and generalized JavaScript taint tracking remain deferred. They require a proven parser/semantic adapter and calibration corpus before becoming release controls.

## References

[1]: https://nextjs.org/docs/pages/guides/environment-variables "Next.js documentation: `NEXT_PUBLIC_` variables are inlined into browser JavaScript"
[2]: https://nextjs.org/docs/app/guides/authentication "Next.js authentication guide: recommended session-cookie options"
[3]: https://nextjs.org/docs/pages/api-reference/config/next-config-js/headers "Next.js headers configuration and CORS options"
[4]: https://nextjs.org/docs/app/guides/data-security "Next.js Data Security — Server Actions as direct POST entry points"
[5]: https://nextjs.org/docs/app/api-reference/file-conventions/proxy "Next.js Proxy convention and Server Function matcher boundary"
