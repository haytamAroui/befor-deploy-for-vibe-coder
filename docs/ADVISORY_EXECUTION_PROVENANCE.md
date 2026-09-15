# Advisory Execution Provenance

## Purpose

PR25 makes advisory provider executions attestable without making them authoritative.

The release boundary is unchanged:

```text
provider/model output -> ADVISORY findings -> gate_effect=NONE

deterministic controls -> policy -> PolicyDecision
```

Execution provenance answers a different question:

> What provider execution produced this advisory result, over which deterministic context, under which declared configuration and budgets, and how does the normalized result relate to the raw provider artifact?

It does **not** answer whether a release is safe, whether a model is correct, or whether an advisory finding should block deployment.

## Provenance object

A live provider execution attaches `AdvisoryExecutionProvenance` to its `AdvisoryImport`.

The object records:

```text
schema_version
provider_id
implementation
implementation_version
model
configuration[]
configuration_sha256
budgets[]
context_sha256
context_selected_files
context_selected_bytes
started_at
completed_at
duration_ms
raw_output
normalized_output_sha256
result_status
authority = ADVISORY_EXECUTION
gate_effect = NONE
```

The provenance object is content-free: it does not contain repository source, provider prompts, raw model output, chain-of-thought, credentials, or provider stderr/stdout.

## Observed vs declared facts

PR25 deliberately distinguishes runtime-observed facts from provider-declared metadata.

### Runtime-observed

The Before Deploy provider runtime records:

- deterministic context digest and selected byte/file counts;
- UTC start/completion timestamps;
- monotonic execution duration;
- final normalized output digest;
- final advisory source status;
- raw-output digest/size when the adapter exposes a bounded raw artifact.

These values are observed or computed by Before Deploy around the provider call.

### Provider-declared

Each provider exposes a redaction-safe `AdvisoryExecutionDescriptor` containing:

- implementation identity/version;
- model identity and attestation state;
- canonical configuration parameters;
- execution budgets.

Provider-declared metadata is still advisory metadata. It must not be treated as independently verified merely because it is recorded in an attestation object.

Future providers can strengthen this contract by sourcing identity from signed/provider-native metadata, but PR25 does not pretend such verification exists when it does not.

## Model identity states

Model identity is explicit rather than guessed.

### `ATTESTED`

`ATTESTED` requires both:

```text
provider
model
```

A provider should use this state only when its integration can actually bind the execution to those values.

### `UNATTESTED`

`UNATTESTED` requires an explicit reason.

For OCR in PR25:

```text
status = UNATTESTED
provider = null
model = null
reason = current OCR JSON contract does not attest configured LLM provider/model
```

Before Deploy does not inspect unrelated environment files or infer a model from local configuration just to fill these fields.

Unknown identity stays unknown.

## Configuration identity

Provider configuration is represented as sorted, unique, redaction-safe name/value parameters.

`configuration_sha256` hashes only that canonical configuration list.

It intentionally does not silently fold model identity, budgets, timestamps, context, or raw output into a field named configuration.

Provider implementation identity, model identity, and budgets remain separately inspectable.

Providers must never place credentials, access tokens, API keys, secret prompts, repository content, or other sensitive values into configuration metadata.

## Budgets

Provider-declared budgets are structured triples:

```text
name
limit
unit
```

They are sorted by name and must have unique names and positive limits.

OCR currently declares:

- accepted raw JSON output bytes;
- preview timeout seconds;
- review timeout seconds.

The deterministic source-context limits from PR24 remain represented by the context manifest and request:

- `max_file_bytes`;
- `max_context_bytes`.

Those are not duplicated as OCR-specific budgets.

## Context lineage

Every execution binds directly to PR24's deterministic context digest:

```text
AdvisoryContext.context_sha256
          |
          v
AdvisoryExecutionProvenance.context_sha256
```

The provenance object also records selected file and byte counts from the validated context.

The runtime validates the context before it obtains the provider execution descriptor or invokes the provider. A malformed/mismatched context therefore produces a preparation error with no execution provenance because no provider execution happened.

## Raw-to-normalized lineage

`load_advisory_file(...)` computes a content-free `AdvisoryRawArtifact` from the exact JSON bytes it normalizes:

```text
sha256
size_bytes
media_type = application/json
schema/source format
```

For live OCR, the bounded output file is loaded through the same path before the temporary file is removed. The resulting digest therefore binds the normalized advisory result to the exact accepted raw OCR JSON bytes without persisting those bytes in Before Deploy reports.

After the provider runtime enforces source identity and rewrites finding authority/gate effect, it computes `normalized_output_sha256` over the final normalized advisory fields and findings (excluding the execution object itself).

The lineage is therefore:

```text
deterministic context_sha256
        |
        v
provider execution
        |
        v
raw JSON bytes --sha256--> AdvisoryRawArtifact
        |
        v
normalization + authority enforcement
        |
        v
normalized_output_sha256
```

A raw artifact can be absent when no raw provider output exists, for example when a provider raises before producing output or an adapter intentionally returns an early context/scope error.

## Failure semantics

The runtime distinguishes execution from preparation.

### Before execution

Examples:

- invalid provider request;
- context preparation/integrity failure;
- invalid execution descriptor.

Result:

```text
status = ERROR
execution = null
```

No execution provenance is fabricated.

### After execution starts

Examples:

- provider exception;
- wrong return type;
- source identity mismatch;
- invalid status semantics;
- invalid raw artifact metadata.

Result:

```text
status = ERROR
execution = AdvisoryExecutionProvenance(...)
gate_effect = NONE
```

The failed call remains traceable but never becomes deterministic authority.

## Timing

The runtime records timezone-aware UTC `started_at` and `completed_at` timestamps.

`duration_ms` is computed from a monotonic clock so system-clock adjustment cannot make a duration negative.

Timing is operational provenance, not deterministic evidence of security or quality.

## Reporting

`review.json` includes structured `raw_artifact` and `execution` fields for every advisory source.

`review.md` summarizes:

- provider/implementation/model attestation state;
- duration;
- context/config/normalized digests;
- raw-output digest and size when available.

Neither report embeds raw provider output or repository source as part of execution provenance.

## Authority invariant

Execution provenance has:

```text
authority = ADVISORY_EXECUTION
gate_effect = NONE
```

Recording more metadata about an LLM/provider does not grant it more authority.

The deterministic release decision never depends on:

- model/provider identity;
- provider configuration;
- model confidence;
- advisory severity;
- execution success/failure;
- raw or normalized provider-output digests.

These values support inspection, correlation, benchmarking, and later Evidence Graph lineage only.

## Next

PR26 can represent provider executions, raw/normalized artifacts, contexts, findings, deterministic observations, and policy decisions as typed Evidence Graph nodes/edges without losing their distinct authority semantics.
