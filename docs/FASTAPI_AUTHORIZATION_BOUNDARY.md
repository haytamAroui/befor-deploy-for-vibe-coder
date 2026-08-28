# FastAPI authorization control boundary

**Status:** Bounded deterministic control, version `0.1.0`.

`SEC-API-AUTHZ-001` inspects Python AST only. For a literal mutating FastAPI route, it recognizes direct `Depends(...)` or `Security(...)` defaults on function parameters. If the route exposes only an authentication-shaped dependency and no explicitly named local authorization marker, it emits one finding.

The recognized authorization marker is intentionally narrow: a direct dependency callable whose name begins with `require_`, `authorize_`, `check_permission`, `enforce_permission`, `require_role`, or `require_scope`. This is a lexical declaration check, not a proof that authorization is correct or enforced.

| Property | Contract |
|---|---|
| Policy | `fastapi-authorization-policy.yaml` only; default and strict profiles are unchanged. |
| Finding evidence | Constant `{artifact: python, issue: authentication_without_authorization_marker}` plus relative path and function line. |
| Vulnerable shape | Literal mutating FastAPI route with a direct authentication-shaped `Depends`/`Security` dependency and no recognized authorization marker. |
| Safe/excluded shapes | Recognized authorization markers, dynamic paths, decorator aliases, route factories, indirect dependencies, computed calls, wrappers, custom dependency semantics, and non-FastAPI decorators. |
| Error behavior | Invalid Python is normalized by the orchestrator as a fail-closed control error. |

The control does not infer identity, roles, scopes, object ownership, tenant isolation, policy semantics, dependency execution, middleware, route reachability, or runtime enforcement. It does not execute Python, FastAPI, application code, tests, builds, package managers, scanners, Docker, or network requests.

Reports never retain route paths, dependency names, function names, source excerpts, or target-controlled values. The policy engine remains the sole release authority.
