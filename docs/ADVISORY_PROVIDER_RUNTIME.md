# Advisory Provider Runtime

## Purpose

Before Deploy has two different execution planes:

- deterministic assurance controls that may participate in `PolicyDecision`;
- advisory discovery providers that may find possible issues but never acquire release authority.

The advisory provider runtime makes that separation a code-level contract instead of a convention tied to OpenCodeReview (OCR).

PR23 introduces a provider-independent request/identity interface and moves the `review --ocr` path behind it. PR24 adds deterministic context preparation before provider execution. OCR remains the first implementation; future native or third-party reviewers must use the same authority and context boundaries.

## Core contract

An advisory provider implements:

```text
identity -> AdvisoryProviderIdentity
review(request: AdvisoryProviderRequest) -> AdvisoryImport
```

The provider-independent request contains:

```text
repository
max_file_bytes
max_context_bytes
from_ref / to_ref
commit
context
```

`context` is either supplied by a trusted caller or built by the runtime before provider execution. In both cases the runtime validates it before the provider is called.

Provider-specific execution settings stay on the provider implementation. For OCR today those include its timeout and accepted JSON-output size.

The runtime is invoked through:

```text
execute_advisory_provider(provider, request)
```

The CLI does not call OCR's execution function directly.

## Authority invariant

Every provider result is untrusted advisory input.

The runtime structurally forces every returned finding to:

```text
authority = ADVISORY
gate_effect = NONE
```

This is true even if a provider attempts to return fields such as:

```text
authority = DETERMINISTIC
gate_effect = BLOCK
```

Those values are rewritten before the result enters the unified review model.

A provider therefore cannot create `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, a waiver, or any other deterministic policy effect.

The deterministic context manifest has its own non-authoritative metadata:

```text
authority = ADVISORY_CONTEXT
gate_effect = NONE
```

Context selection constrains provider input; it does not become release authority.

## Stable provider identity

Every provider declares a runtime identity:

```text
provider_id
input_name
source
source_format
```

The returned `AdvisoryImport` must agree with the declared `source` and `source_format`. An inconsistent result is discarded and represented as an advisory source error.

This prevents a provider from presenting itself as the deterministic core or another provider in the unified review plane.

PR25 will extend provider execution provenance with model/config/context/budget/timing lineage. PR24 intentionally records only deterministic source-context lineage and a bounded context summary.

## Deterministic context preparation

Before calling a provider, the runtime now ensures that `AdvisoryProviderRequest.context` is a validated `AdvisoryContext`.

If the caller does not provide one, the runtime builds it from the request scope using the deterministic context selector.

The selector:

1. starts from the provider-independent changed-file preview;
2. materializes exact workspace or Git-tree bytes;
3. rejects excluded paths, symlinks, binary/non-UTF-8 inputs, and oversized files;
4. applies a stable whole-file aggregate byte budget;
5. hashes every selected file;
6. computes a canonical content-free context-manifest digest.

For range and commit modes, bytes are read from the resolved target Git tree rather than the current checkout.

See [ADVISORY_CONTEXT.md](ADVISORY_CONTEXT.md) for the full selection and provenance contract.

## Failure isolation

Provider execution and context preparation are isolated from release authority.

If context preparation fails, a provider raises a normal Python exception, returns the wrong result type, violates its declared identity, or receives an invalid common review scope, the runtime converts the failure into:

```text
status = ERROR
findings = []
```

under that provider's advisory identity.

The deterministic scan result and its process exit code remain unchanged.

`KeyboardInterrupt`, `SystemExit`, and other `BaseException` subclasses are not swallowed by this boundary.

## Scope contract

The generic runtime validates provider-independent request invariants:

- `max_file_bytes` must be positive;
- `max_context_bytes` must be positive;
- `from_ref` and `to_ref` must be supplied together;
- `commit` cannot be combined with `from_ref` / `to_ref`;
- a supplied context must match the request repository, scope, and byte limits;
- context manifest/content hashes must validate before provider execution.

Provider-specific scope attestation remains inside each provider implementation.

## OCR adapter

`OcrAdvisoryProvider` maps the generic request into the existing bounded `OcrAdvisoryOptions` and isolated OCR execution path.

OCR is a transitional case because the external CLI chooses its own file set instead of directly consuming `AdvisoryContext.files`.

Before OCR starts, the provider compares:

```text
Before Deploy deterministic preview reviewable paths
                ==
AdvisoryContext selected paths
```

If they differ, OCR is not invoked and the source reports `CONTEXT_LIMITED`. This prevents OCR from silently widening beyond the aggregate/encoding/path constraints established by PR24.

If the sets match, the existing OCR two-stage contract still applies:

1. OCR preflight may select a subset but may not expand beyond the deterministic allowed set;
2. the final OCR run manifest, when supported, must not expand or drift from preflight;
3. violating findings are discarded.

The legacy lower-level `run_ocr_advisory(...)` function remains an implementation-level compatibility surface and retains its existing tests. The supported orchestration path is:

```text
before-deploy review --ocr
        |
        v
execute_advisory_provider
        |
        +--> deterministic AdvisoryContext
        |
        v
OcrAdvisoryProvider
        |
        v
bounded OCR adapter + scope attestation
        |
        v
AdvisoryImport
        |
        v
ADVISORY / gate_effect=NONE
```

## Context visibility

A successful provider result includes a bounded context summary in its advisory source metadata:

```text
context_sha256=<digest>
selected_files=<count>
selected_bytes=<used>/<budget>
excluded_files=<count>
```

The context module also provides content-free JSON and Markdown renderers for inspection and future artifact persistence. Raw source content is never serialized by those renderers.

PR25 will turn this context identity into explicit provider execution provenance rather than treating the source message as the long-term attestation format.

## Dependency direction

The intended dependency direction is:

```text
CLI
 |
 v
AdvisoryProvider runtime
 |
 +--> deterministic context selector
 |
 +--> OCR provider
 +--> future providers

Deterministic scan ------------------+
                                     |
Advisory imports/providers ----------+--> unified review/reporting

Deterministic PolicyDecision never depends on provider output.
```

Providers may consume deterministic context manifests and exact materialized source bytes. They do not feed semantic judgments back into deterministic policy evaluation.

## What PR24 does not add

PR24 does not add:

- a second AI provider;
- provider auto-discovery;
- arbitrary executable or prompt configuration;
- native LLM execution;
- semantic/model-driven context ranking;
- embeddings or vector search;
- AST/function-level chunking;
- model/config/token/cost provenance;
- provider timing attestations;
- Evidence Graph correlation;
- any policy setting that promotes AI severity into a deterministic block.

Those concerns remain deliberately staged.

## Next increments

PR25 adds provider execution provenance and budget/timing contracts, including first-class model/config/context lineage.

PR26 can then build Evidence Graph v1 on top of provider results whose input scope and execution lineage are explicit.
