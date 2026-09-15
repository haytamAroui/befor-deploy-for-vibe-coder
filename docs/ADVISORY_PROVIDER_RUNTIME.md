# Advisory Provider Runtime

## Purpose

Before Deploy has two different execution planes:

- deterministic assurance controls that may participate in `PolicyDecision`;
- advisory discovery providers that may find possible issues but never acquire release authority.

The advisory provider runtime makes that separation a code-level contract instead of a convention tied to OpenCodeReview (OCR).

PR23 introduced the provider-independent execution boundary. PR24 added deterministic context preparation. PR25 adds explicit execution provenance: implementation/model/configuration identity, budgets, timing, context lineage, and raw-to-normalized output digests.

OCR remains the first implementation; future native or third-party reviewers must use the same authority, context, and provenance boundaries.

## Core contract

An advisory provider implements:

```text
identity -> AdvisoryProviderIdentity
execution_descriptor(request) -> AdvisoryExecutionDescriptor
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

The execution descriptor contains only redaction-safe provider metadata:

```text
implementation
implementation_version
model identity + attestation state
configuration[]
budgets[]
```

Provider-specific settings stay on provider implementations. For OCR those include its timeout and accepted JSON-output size.

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

This is true even if a provider attempts to return:

```text
authority = DETERMINISTIC
gate_effect = BLOCK
```

Those values are rewritten before the result enters the unified review model.

A provider therefore cannot create `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, a waiver, or any other deterministic policy effect.

The deterministic context manifest and execution provenance have their own non-authoritative metadata:

```text
authority = ADVISORY_CONTEXT
gate_effect = NONE

authority = ADVISORY_EXECUTION
gate_effect = NONE
```

More provider metadata never grants more release authority.

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

## Execution identity and provenance

Before invocation, the runtime validates and canonicalizes `AdvisoryExecutionDescriptor`.

The descriptor separates:

- provider implementation identity/version;
- model identity and whether that identity is actually attested;
- redaction-safe configuration parameters;
- provider-declared execution budgets.

Configuration parameter and budget names must be unique and are canonicalized by name.

`configuration_sha256` hashes only the canonical configuration list. Model identity, implementation identity, budgets, context, timing, and output digests remain separate fields.

After execution begins, the runtime records:

```text
context_sha256
context selected file/byte counts
started_at
completed_at
duration_ms
raw-output digest/size when available
normalized_output_sha256
result_status
```

`duration_ms` uses a monotonic clock; UTC timestamps provide human/audit chronology.

See [ADVISORY_EXECUTION_PROVENANCE.md](ADVISORY_EXECUTION_PROVENANCE.md) for the complete lineage contract.

## Model identity

Model identity is never guessed.

`ATTESTED` requires both a provider and model name.

`UNATTESTED` requires a reason explaining why the integration cannot bind the execution to a trustworthy provider/model identity.

OCR currently reports `UNATTESTED` because its accepted JSON contract does not attest the configured LLM provider/model. Before Deploy does not infer those fields from unrelated local configuration or environment state.

## Deterministic context preparation

Before calling a provider, the runtime ensures that `AdvisoryProviderRequest.context` is a validated `AdvisoryContext`.

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

## Raw-to-normalized lineage

The advisory JSON loader records a content-free digest of the exact accepted raw JSON bytes:

```text
sha256
size_bytes
media_type
schema/source_format
```

For live OCR this digest is computed while the bounded temporary output still exists. Raw OCR JSON is not copied into the unified report.

After source/status validation and structural authority enforcement, the provider runtime computes `normalized_output_sha256` over the normalized advisory source fields and findings, excluding the execution object itself.

This gives the trace:

```text
context_sha256
      |
      v
provider execution
      |
      v
raw_output.sha256
      |
      v
normalization + authority enforcement
      |
      v
normalized_output_sha256
```

## Failure isolation

Provider execution, descriptor validation, and context preparation are isolated from release authority.

Failures before provider invocation produce an advisory source error with no execution provenance because no execution occurred. Examples include:

- invalid request scope;
- context preparation/integrity failure;
- invalid execution descriptor.

Failures after execution begins retain execution provenance. Examples include:

- provider exception;
- unsupported return type;
- source identity mismatch;
- invalid status semantics;
- invalid raw-output provenance.

In every case:

```text
status = ERROR
findings = []
gate_effect = NONE
```

The deterministic scan result and process exit code remain unchanged.

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

OCR declares:

```text
implementation = open-code-review-cli
implementation_version = null
model.status = UNATTESTED
```

and redaction-safe configuration including its Before Deploy adapter contract, audience, JSON format, and supported OCR manifest schema.

It also declares accepted JSON-output and timeout budgets.

OCR is a transitional case because the external CLI chooses its own file set instead of directly consuming `AdvisoryContext.files`.

Before OCR starts, the provider compares:

```text
Before Deploy deterministic preview reviewable paths
                ==
AdvisoryContext selected paths
```

If they differ, OCR is not invoked and the source reports `CONTEXT_LIMITED`.

If the sets match, the existing OCR two-stage contract still applies:

1. OCR preflight may select a subset but may not expand beyond the deterministic allowed set;
2. the final OCR run manifest, when supported, must not expand or drift from preflight;
3. violating findings are discarded.

The legacy lower-level `run_ocr_advisory(...)` function remains an implementation-level compatibility surface.

The supported orchestration path is:

```text
before-deploy review --ocr
        |
        v
execute_advisory_provider
        |
        +--> deterministic AdvisoryContext
        +--> execution descriptor
        |
        v
OcrAdvisoryProvider
        |
        v
bounded OCR adapter + scope attestation
        |
        v
raw artifact digest -> normalized AdvisoryImport
        |
        v
AdvisoryExecutionProvenance
        |
        v
ADVISORY / gate_effect=NONE
```

## Reporting

`review.json` includes structured `raw_artifact` and `execution` fields per advisory source.

`review.md` summarizes provider/implementation/model state, duration, context/config/normalized digests, and raw-output digest/size when available.

Raw repository content, provider raw output, chain-of-thought, credentials, and stderr/stdout are not embedded into execution provenance.

## Dependency direction

The intended dependency direction is:

```text
CLI
 |
 v
AdvisoryProvider runtime
 |
 +--> deterministic context selector
 +--> execution provenance
 |
 +--> OCR provider
 +--> future providers

Deterministic scan ------------------+
                                     |
Advisory imports/providers ----------+--> unified review/reporting

Deterministic PolicyDecision never depends on provider output.
```

Providers may consume deterministic context manifests and exact materialized source bytes. They do not feed semantic judgments back into deterministic policy evaluation.

## What PR25 does not add

PR25 does not add:

- a second AI provider;
- provider auto-discovery;
- native LLM execution;
- semantic/model-driven context ranking;
- embeddings or vector search;
- AST/function-level chunking;
- provider cost accounting where the provider does not expose trustworthy usage data;
- verified OCR model identity that OCR itself does not attest;
- Evidence Graph nodes;
- any policy setting that promotes AI severity into a deterministic block.

## Next increment

PR26 builds Evidence Graph v1 on top of explicit deterministic context, provider execution lineage, raw/normalized artifacts, advisory findings, deterministic observations, and policy decisions.
