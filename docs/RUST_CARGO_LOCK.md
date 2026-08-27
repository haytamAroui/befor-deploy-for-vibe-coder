# Rust/Cargo Lockfile Boundary

**Status:** Implemented as the opt-in native control `SEC-RUST-CARGO-LOCK-001` version `0.1.0`.

## Purpose and authority boundary

Cargo distinguishes `Cargo.toml`, which broadly describes dependencies, from `Cargo.lock`, which contains exact dependency information maintained by Cargo. Its guidance recommends committing `Cargo.lock` when in doubt.[1] Cargo also documents `src/main.rs` as the conventional source path for a binary target, while allowing other configured and automatically discovered target forms.[2]

> **Authority boundary:** This control produces only a normalized finding or normalized execution state for its strict file-presence condition. The versioned deterministic policy engine is the sole release authority. The project profile, capability registry, domain contract, security analysis plan, coverage audit, and documentation remain diagnostic or descriptive and cannot independently change a release decision.

## Exact detection contract

The control is selected only by `rules/rust-cargo-lock-policy.yaml`. Its capability is compatible only with a `Rust` project profile. A finding exists only when every static condition below is satisfied.

| Static condition | Required observation |
|---|---|
| Root manifest | An inventory-included root `Cargo.toml` is present and parses as TOML. |
| Conventional binary marker | An inventory-included root-relative `src/main.rs` file is present. Its content is not read. |
| Direct dependency form | The manifest has a direct, non-empty `dependencies` TOML table. Dependency names and values are not retained or interpreted. |
| Missing evidence | No inventory-included root `Cargo.lock` exists. |
| Finding result | One `SEC-RUST-CARGO-LOCK-001` finding at `Cargo.toml:1`, with constant evidence `ecosystem=cargo`, `target=conventional_binary`, and `issue=cargo_lock_missing`. |

A root `Cargo.lock` prevents this **presence-only** finding even when the file is empty, malformed, stale, incompatible, inconsistent with `Cargo.toml`, or otherwise unusable. The lockfile is never parsed or validated by this control.

## Non-applicability and errors

Missing `Cargo.toml` or missing `src/main.rs` produces `NOT_APPLICABLE`; the control therefore does not infer a library, workspace, `src/bin` target, manually configured `[[bin]]` target, custom source path, nested project, or monorepo. A valid manifest with absent, empty, or non-table `dependencies` completes without a finding because it does not declare a direct dependency form supported by this contract.

An unreadable or invalid root manifest in the conventional binary shape produces `ERROR` with only `CARGO_MANIFEST_UNREADABLE` or `CARGO_MANIFEST_INVALID` metadata. Parser messages, source excerpts, dependency names or values, and target-controlled text are discarded. A policy that marks the control required then fails closed through the existing deterministic policy engine.

| Situation | Execution state | Finding from this control |
|---|---|---|
| Conventional binary, direct non-empty dependencies, no root lockfile | `COMPLETED` | One normalized presence finding. |
| Conventional binary, direct non-empty dependencies, root lockfile present | `COMPLETED` | None. |
| Library/workspace/custom-target or unsupported direct-dependency form | `NOT_APPLICABLE` or completed with no finding, as specified above | None. |
| Conventional binary with unreadable or invalid root manifest | `ERROR` | None; required policy selection fails closed. |

## Explicit exclusions

The control does **not** run Cargo, `rustc`, Rust code, package scripts, builds, tests, resolvers, downloads, registries, networks, or target commands. It does not inspect dependency names, version values, dependency constraints, `dev-dependencies`, `build-dependencies`, target-specific dependencies, features, registry configuration, git dependencies, transitive dependencies, `Cargo.lock` content, integrity, checksums, freshness, manifest-lock consistency, vulnerability status, provenance, toolchain compatibility, source reachability, runtime behavior, or deployment behavior.

A clean result means only that this one conventional root binary form has a root file named `Cargo.lock`; it is not evidence of Cargo dependency integrity, reproducible builds, absence of vulnerable crates, correct workspace configuration, runtime safety, production readiness, or compliance.

## Fixtures and reporting

The regression corpus includes a vulnerable missing-lock fixture, a root-lock-present fixture, a library-only exclusion fixture, and an invalid-manifest fixture. Integration coverage confirms opt-in `BLOCK`, default-policy isolation, `PASS`, normalized `ERROR`, one-to-one capability/contract mapping, catalog provenance, package inclusion, and redaction across JSON, Markdown, and SARIF.

Normalized reports contain only the fixed rule ID, execution state, relative finding location, and constant evidence. They do not retain Cargo dependency names or values, arbitrary manifest text, parser messages, lockfile content, Rust source, command output, or secrets.

## References

[1]: https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html "Cargo Book — Cargo.toml vs Cargo.lock"
[2]: https://doc.rust-lang.org/cargo/reference/cargo-targets.html "Cargo Book — Cargo targets"
