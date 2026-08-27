# FastAPI Dynamic Route Review Boundary

**Status:** Implemented as a structural review state in `SEC-API-001` version `0.2.0`. The state is deliberately not a finding, waiver target, policy rule, coverage score, or release decision. It identifies only FastAPI route-decorator shapes that the static authentication-declaration check does not interpret.

## Purpose

The FastAPI route control still evaluates supported **static** mutating route decorators for a visible `Depends` or `Security` signal, or an exact policy allowlist entry. FastAPI exposes path-operation decorators on application/router objects and supports dependency declarations on those decorators.[1] [2] Those observable declarations remain useful bounded evidence, but they cannot prove real authentication, authorization, tenant isolation, object ownership, dependency semantics, or runtime registration.

When a recognized FastAPI path-operation decorator cannot be analyzed by the static contract, the control completes normally and emits a deterministic execution metadata state. No security finding is emitted merely because a path or method expression is dynamic. This prevents a dynamic construction from being silently presented as static coverage while avoiding a false claim that it is unauthenticated or vulnerable.

> **Authority boundary:** `REVIEW_REQUIRED` is diagnostic metadata only. The versioned policy engine remains the sole release authority. It receives no finding from this state, so the state alone cannot return `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, `PASS`, or `NOT_EVALUATED`.

## Review-state contract

| State reason | Observed source shape | Result |
|---|---|---|
| `DYNAMIC_PATH` | The first argument of a recognized `get`, `post`, `put`, `patch`, `delete`, or `api_route` decorator is not a literal slash-prefixed string. | The decorator is not considered an authenticated or unauthenticated route. One review location is recorded. |
| `DYNAMIC_METHODS` | `api_route` has no `methods` declaration, or its `methods` value is not a literal list, tuple, or set containing only string constants. | The decorator is not considered a static route-method pair. One review location is recorded. |
| `NOT_REQUIRED` | No supported dynamic-route shape was observed. | The static control may still have findings or no findings. This is not a statement that the route surface is complete or secure. |

The metadata contains only a state, a deduplicated count, and at most fifty deterministic `path:line:reason` references. Additional references are counted and marked as truncated. The route expression, computed path value, computed method value, source excerpt, dependency contents, request data, and credentials are not retained.

## Report behavior

The state appears under the normalized `metadata` of the completed `SEC-API-001` execution in JSON, Markdown, and SARIF. Markdown renders execution metadata in a separate table column. SARIF places the full normalized execution list under `beforeDeployControlExecutions`; it does not create a SARIF result for a review state.

| Report situation | Gate result | Security findings | Review metadata |
|---|---|---|---|
| Dynamic FastAPI decorator only | Unchanged by the review state | None from the dynamic structure alone | `REVIEW_REQUIRED` |
| Static mutating decorator without a visible dependency | Determined normally by policy | Existing `SEC-API-001` finding | `NOT_REQUIRED` if no dynamic decorator also exists |
| Static declared dependency | Determined normally by policy | No finding from the bounded declaration pattern | `NOT_REQUIRED` if no dynamic decorator also exists |

## Explicit exclusions

The control does not resolve variables, imports, aliases, `include_router`, custom decorator factories, dynamic router registration, `add_api_route`, router prefixes, method computation, middleware, global dependencies, application startup behavior, or runtime OpenAPI. It does not prove whether a visible `Depends` or `Security` call authenticates a user, enforces a role, checks object-level authorization, or is applied to the final registered route. A static route with no finding is not a guarantee of API security.

## Fixture matrix

The regression set contains a dynamic path, a dynamic `api_route` methods list, an `api_route` without `methods`, a static unguarded mutation route, and a non-FastAPI source file. The integration fixture combines dynamic path and method states with a static health route and verifies that the scan passes, produces no FastAPI finding, and renders the review metadata in all three report formats.

## References

[1]: https://fastapi.tiangolo.com/reference/apirouter/ "FastAPI APIRouter reference"
[2]: https://fastapi.tiangolo.com/tutorial/dependencies/dependencies-in-path-operation-decorators/ "FastAPI dependencies in path operation decorators"
