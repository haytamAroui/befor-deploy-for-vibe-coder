# Next.js and TypeScript Control Milestone

**Status:** Approved implementation scope
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

## Applicability and decision semantics

The adaptive capability catalog marks all three controls as requiring the **Next.js** framework signal. A policy may select them for every repository; a non-Next repository receives explicit `NOT_APPLICABLE` executions rather than silent omission. A Next.js project without one of the risky patterns receives a completed execution with zero findings.

Each finding has a stable fingerprint, redacted evidence consisting only of path, line, and variable/cookie/header identifiers, and ordinary policy handling. The project profile never decides `PASS` or suppresses a finding.

## Test matrix

| Fixture | Expected result |
|---|---|
| Secure Next.js fixture | `PASS`; static public analytics ID, secure session cookie options, and specific/credentialed CORS configuration are accepted. |
| Vulnerable Next.js fixture | `BLOCK`; exposes a named public secret, writes a session cookie with explicitly unsafe options, and uses wildcard origin plus credentials. |
| Python/FastAPI fixture | All three controls are `NOT_APPLICABLE`; existing Python controls retain their previous behavior. |
| Dynamic/unknown constructs | No speculative finding. The report retains the static-analysis boundary in its limitations. |

## Deferred controls

Server Actions authorization, client/server data boundary analysis, dynamic route handlers, middleware authorization, and generalized JavaScript taint tracking remain deferred. They require a proven parser/semantic adapter and calibration corpus before becoming release controls.

## References

[1]: https://nextjs.org/docs/pages/guides/environment-variables "Next.js documentation: `NEXT_PUBLIC_` variables are inlined into browser JavaScript"
[2]: https://nextjs.org/docs/app/guides/authentication "Next.js authentication guide: recommended session-cookie options"
[3]: https://nextjs.org/docs/pages/api-reference/config/next-config-js/headers "Next.js headers configuration and CORS options"
