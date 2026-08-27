# Go Reference Capability Pack

**Status:** In implementation. This document defines the first scoped Go capability pack; it does not claim comprehensive Go security analysis, framework support, compliance, or release authority.

## Scope

The initial Go pack introduces two narrow native controls and one optional external adapter. The deterministic policy engine remains the only component that can produce a release decision. Profiles may configure the adapter, but no capability manifest, requirement signal, project profile, or coverage state can activate an unconfigured scanner.

| Implementation | Security-domain mapping | Bounded purpose | Excluded from scope |
|---|---|---|---|
| `SEC-GO-MODULE-001` | Software supply chain | Require root `go.sum` only when root `go.mod` contains a direct or block-form `require` declaration. | Nested modules, checksum contents, dependency resolution, dependency vulnerabilities, and artifact integrity. |
| `SEC-GO-TLS-001` | Transport security | Detect a direct `tls.Config` composite literal that explicitly sets `InsecureSkipVerify: true`. | Aliases, computed values, custom verification callbacks, non-Go TLS stacks, and runtime behavior. |
| `SEC-GOSEC-001` | Injection, SSRF, path traversal | Optional, policy-configured local Gosec JSON adapter with fixed arguments and redacted normalized findings. | Installation, target-supplied commands/configuration, AI-fix mode, dependency download, remote configuration, and any coverage outside the upstream result. |

## Adapter execution boundary

Gosec documents AST, SSA, and taint-analysis checks spanning multiple Go security categories. It also documents JSON output with `-fmt=json -out`, `-no-fail`, generated-code exclusion, and optional suppression tracking.[1] Before Deploy will invoke only a preinstalled executable from an explicit policy profile. It will not execute the documented Gosec AI-fix options, install a binary, inherit credentials, pass target-supplied flags, or retain upstream source snippets/details.

The adapter passes a fixed local module target and sets `GOPROXY=off` in its isolated process environment. This is intentional: the Go module reference explains that normal module resolution may contact proxy or version-control servers, while `GOPROXY=off` prevents that communication.[2] If dependencies are absent from the local environment, the adapter must return an explicit execution error; it must not download them.

The initial optional policy pins Gosec **v2.29.0**, released by the upstream project on 26 August 2026.[3] The policy pin is an operational review point, not a claim that the tool is automatically installed or trustworthy for all environments.

## Domain and coverage boundary

The Go pack activates only concrete Go-related catalog mappings: software supply chain, transport security, injection, SSRF, and path traversal. Native controls cover only the first two. Injection, SSRF, and path traversal have an approved but unselected Gosec adapter in standard profiles, so they report `NOT_SELECTED`; the explicit Go external-adapters profile can select Gosec. Any result remains limited by the upstream rule, tool version, source/build configuration, and local dependency availability.

> `COVERED` means that the selected mapped capability completed within its declared scope. It does not mean that Go code, its dependencies, production network posture, or any security domain is exhaustively secure.

## Fixture policy

Every Go control/adaptor must retain secure, vulnerable, unsupported, and false-positive fixtures. Adapter tests use a fake preinstalled executable that produces an intentionally redacted-shaped JSON report; live scanner installation and network access are not part of the test suite.

## References

[1]: https://github.com/securego/gosec "securego/gosec README — scan modes, output formats, exit behavior, rule categories, suppression controls, and AI-fix options"
[2]: https://go.dev/ref/mod "Go Modules Reference — module resolution and GOPROXY behavior"
[3]: https://github.com/securego/gosec/releases "securego/gosec releases — v2.29.0"
