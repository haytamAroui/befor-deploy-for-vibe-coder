# Advisory Provider Runtime

## Purpose

Before Deploy has two different execution planes:

- deterministic assurance controls that may participate in `PolicyDecision`;
- advisory discovery providers that may find possible issues but never acquire release authority.

The advisory provider runtime makes that separation a code-level contract instead of a convention tied to OpenCodeReview (OCR).

PR23 introduces a provider-independent request/identity interface and moves the `review --ocr` path behind it. OCR remains the first implementation; future native or third-party reviewers must use the same authority boundary.

## Core contract

An advisory provider implements:

```text
identity -> AdvisoryProviderIdentity
review(request: AdvisoryProviderRequest) -> AdvisoryImport
```

The provider-independent request contains only the repository review scope needed at this stage:

```text
repository
max_file_bytes
from_ref / to_ref
commit
```

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

PR25 will extend provider execution provenance with model/config/context/budget/timing lineage. PR23 intentionally establishes only the stable execution boundary needed before those richer attestations exist.

## Failure isolation

Provider execution is isolated from release authority.

If a provider raises a normal Python exception, returns the wrong result type, violates its declared identity, or receives an invalid common review scope, the runtime converts the failure into:

```text
status = ERROR
findings = []
```

under that provider's advisory identity.

The deterministic scan result and its process exit code remain unchanged.

`KeyboardInterrupt`, `SystemExit`, and other `BaseException` subclasses are not swallowed by this boundary.

## Scope contract

The generic runtime validates only provider-independent request invariants:

- `max_file_bytes` must be positive;
- `from_ref` and `to_ref` must be supplied together;
- `commit` cannot be combined with `from_ref` / `to_ref`.

Provider-specific scope attestation remains inside each provider implementation.

For OCR, the existing two-stage contract is unchanged:

1. Before Deploy computes the deterministic changed-file preview;
2. OCR preflight may select a subset but may not expand beyond it;
3. the final OCR run manifest, when supported, must not expand or drift from preflight;
4. violating findings are discarded.

Moving OCR behind `AdvisoryProvider` does not weaken or duplicate that logic.

## OCR adapter

`OcrAdvisoryProvider` maps the generic request into the existing bounded `OcrAdvisoryOptions` and isolated OCR execution path.

The legacy lower-level `run_ocr_advisory(...)` function remains an implementation-level compatibility surface and retains its existing tests. The supported CLI orchestration path is now:

```text
before-deploy review --ocr
        |
        v
OcrAdvisoryProvider
        |
        v
execute_advisory_provider
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

## Dependency direction

The intended dependency direction is:

```text
CLI
 |
 v
AdvisoryProvider runtime
 |
 +--> OCR provider
 +--> future providers

Deterministic scan ------------------+
                                     |
Advisory imports/providers ----------+--> unified review/reporting

Deterministic PolicyDecision never depends on provider output.
```

Providers may consume provider-independent review scope and, in future increments, deterministic context manifests. They do not feed semantic judgments back into deterministic policy evaluation.

## What PR23 does not add

PR23 does not add:

- a second AI provider;
- provider auto-discovery;
- arbitrary executable or prompt configuration;
- native LLM execution;
- context selection;
- model/config/token/cost provenance;
- Evidence Graph correlation;
- any policy setting that promotes AI severity into a deterministic block.

Those concerns remain deliberately staged.

## Next increments

PR24 adds deterministic, reproducible AI context selection with inspectable provenance.

PR25 adds provider execution provenance and budget/timing contracts.

PR26 can then build Evidence Graph v1 on top of provider results whose input scope and execution lineage are explicit.
