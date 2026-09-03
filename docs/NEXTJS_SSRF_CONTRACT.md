# Bounded Next.js SSRF Contract

`SEC-NEXT-SSRF-001` covers one source-visible App Router flow only:

`fetch(request.nextUrl.searchParams.get(...))`

The control applies only to `route.js`, `route.jsx`, `route.ts`, and `route.tsx` files in repositories where Next.js is detected from `package.json`. It recognizes named exported async `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` handlers.

## Explicit exclusions

The control does not follow local aliases, `new URL(request.url)`, request bodies, FormData, transformations, helper calls, wrappers, branches, client libraries, or interprocedural flow. It does not infer DNS resolution, redirect behavior, private-address reachability, proxy policy, or semantic allowlist correctness.

This is one reviewed control contract mapped to `DOMAIN-SSRF-001`. Findings are evidence for the existing deterministic policy engine; the detector does not make release decisions.
