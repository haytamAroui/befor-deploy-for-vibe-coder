# FastAPI input-validation control boundary

**Status:** Bounded deterministic control, version `0.1.0`.

`SEC-API-INPUT-001` is an opt-in static Python AST control. It checks only direct function parameters annotated with the bare names `dict` or `Any` when the function has a supported literal mutating FastAPI route decorator: `post`, `put`, `patch`, or `delete`. Such a shape produces one normalized medium-severity finding requiring an explicit validation model.

| Property | Contract |
|---|---|
| Policy | `rules/fastapi-input-validation-policy.yaml` only; default and strict profiles are unchanged. |
| Finding evidence | Constant `{artifact: python, issue: untyped_fastapi_body}` plus relative path and parameter line. |
| Vulnerable shape | Literal mutating route decorator with a direct bare `dict` or `Any` parameter. |
| Safe/excluded shapes | Explicit model annotations, generic aliases such as `dict[str, str]`, model aliases, non-literal route paths, non-mutating routes, decorator aliases, factories, and indirect parameters. |
| Error behavior | Invalid Python is normalized by the orchestrator as a fail-closed control error. |

The control does not prove that a parameter is actually bound to a request body. It does not parse FastAPI semantics, resolve aliases, inspect model definitions, infer runtime validators, evaluate normalization, enforce size or business limits, follow dataflow, or determine whether a route is reachable. It does not execute Python, FastAPI, application code, tests, builds, package managers, Docker, Compose, external scanners, or network requests.

Reports never retain source excerpts, parameter names, route paths, model names, arbitrary configuration values, or target-controlled prose. The policy engine remains the sole release authority: this control can create only its own normalized finding when explicitly selected by policy, and cannot select tools, create waivers, change policy, or override a release outcome.
