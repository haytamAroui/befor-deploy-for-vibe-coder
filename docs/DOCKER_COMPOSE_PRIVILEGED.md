# Docker Compose Privileged-Service Boundary

**Status:** Implemented as the opt-in native control `SEC-COMPOSE-PRIVILEGED-001` version `0.1.0`.

## Purpose and authority boundary

Docker describes a Compose file as configuration for an application’s services, networks, volumes, and related resources.[1] Its service reference states that `privileged` configures a service container with elevated privileges and that support and effects are platform-specific.[2]

> **Authority boundary:** This control observes only one literal YAML property in one constrained file shape. It creates a normalized finding or execution state; the versioned deterministic policy engine remains the sole release authority. The capability registry, domain contract, security analysis plan, coverage audit, documentation, and static repository evidence do not independently change a release decision.

## Exact detection contract

The control is selected only by `rules/docker-compose-privileged-policy.yaml`. It inspects only inventory-included root files named `compose.yaml`, `compose.yml`, `docker-compose.yaml`, or `docker-compose.yml`. No subdirectory or alternate filename is evaluated.

| Static condition | Required observation |
|---|---|
| Document | Exactly one parseable YAML document with a top-level mapping. |
| Services structure | A direct scalar `services` key whose value is a YAML mapping. |
| Service structure | A direct scalar service key whose value is a YAML mapping without `extends` or `profiles`. Service names are not retained. |
| Privilege property | A direct scalar `privileged` key with an **unquoted lowercase YAML boolean** scalar whose textual value is exactly `true`. |
| Finding result | One `SEC-COMPOSE-PRIVILEGED-001` finding for each supported service at the value line, with constant evidence `artifact=compose` and `issue=privileged_service`. |

A direct literal `privileged: false` or absence of the property produces no finding. Findings are ordered by relative path and line. They do not retain service names, image references, YAML values, source fragments, or parser output.

## Non-applicability and errors

No supported root Compose filename yields `NOT_APPLICABLE`. Valid supported files outside the direct shape complete without a finding; this is not a claim that their services are unprivileged or safe.

A supported Compose file that is unreadable, invalid UTF-8, or invalid YAML produces `ERROR` with only `COMPOSE_YAML_UNREADABLE`, `COMPOSE_YAML_INVALID_ENCODING`, or `COMPOSE_YAML_INVALID` metadata. Raw I/O or parser diagnostics and source text are discarded. A policy requiring the control then fails closed through the existing deterministic policy engine.

| Situation | Execution state | Finding from this control |
|---|---|---|
| Supported direct service with `privileged: true` | `COMPLETED` | One normalized finding per service. |
| Supported direct service with `privileged: false` | `COMPLETED` | None. |
| Dynamic, reused, nested, or unsupported shape | `COMPLETED` or `NOT_APPLICABLE`, as specified above | None; no safety conclusion. |
| Unreadable, invalid-encoding, or invalid YAML supported file | `ERROR` | None; a required policy selection fails closed. |

## Explicit exclusions

The control excludes anchors, aliases, merge keys, `${...}` interpolation, `{{...}}` templates, multi-document YAML, top-level non-mappings, non-mapping services, `include`, `extends`, profiles, quoted or alternative boolean spellings, dynamic names/values, nested Compose files, Compose extensions, images, Dockerfiles, commands, ports, networks, mounts, capabilities, secrets, host configuration, container runtime state, Kubernetes, Helm, CloudFormation, Terraform, and deployment behavior.

The control does **not** execute Docker, Docker Compose, containers, images, source code, commands, scripts, builds, tests, resolvers, downloads, registries, networks, providers, or cloud APIs. It does not prove or disprove effective runtime privilege, host isolation, Linux capabilities, image safety, orchestration policy, production suitability, or compliance.

## Fixtures and reporting

The regression corpus includes a direct vulnerable service, a direct `false` service, a dynamic/reused/profiled exclusion corpus, and malformed YAML. Integration coverage confirms opt-in `BLOCK`, default-policy isolation, `PASS`, normalized `ERROR`, one-to-one capability/contract mapping, catalog provenance, and redaction in JSON, Markdown, and SARIF.

## References

[1]: https://docs.docker.com/reference/compose-file/ "Docker Docs — Compose file reference"
[2]: https://docs.docker.com/reference/compose-file/services/ "Docker Docs — Define services in Docker Compose"
