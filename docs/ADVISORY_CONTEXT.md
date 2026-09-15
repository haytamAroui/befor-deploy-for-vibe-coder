# Deterministic Advisory Context

## Purpose

Before Deploy treats advisory-provider context as an input-selection problem, not as an LLM prompt problem.

PR24 introduces a deterministic context builder that selects, materializes, hashes, and budgets the exact source bytes made available to advisory providers. The result is reproducible, inspectable, and non-authoritative.

Context metadata always carries:

```text
authority = ADVISORY_CONTEXT
gate_effect = NONE
```

Context selection cannot create `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR`, a waiver, or any other release decision.

## Selection inputs

The selector receives the same provider-independent review scope established by PR23:

```text
repository
max_file_bytes
max_context_bytes
from_ref / to_ref
commit
```

`max_file_bytes` bounds each file. `max_context_bytes` bounds the total materialized provider input.

The default aggregate limit is 4,000,000 bytes. PR25 will add execution-time budget/timing provenance; PR24 is limited to deterministic source-byte selection.

## Stable ordering and whole-file selection

Changed paths are considered in stable repository-relative path order.

A selected file is included as a whole UTF-8 file. PR24 intentionally does not add semantic chunking, embeddings, model-driven relevance, or AST ranking.

When the next whole file would exceed `max_context_bytes`, that file is excluded with:

```text
reason = context_budget
```

The selector never takes an arbitrary byte prefix merely to fill the remaining budget. This keeps line ranges and content hashes meaningful.

## Source byte semantics

The exact byte source depends on review mode.

### Workspace mode

Workspace review materializes the current working-tree file bytes. Symlinks are rejected rather than followed, including symlinked path components.

### Range mode

For:

```text
--from <source> --to <target>
```

selected bytes are read from the resolved `<target>` Git tree, not from whatever happens to exist in the caller's current checkout.

### Commit mode

For:

```text
--commit <revision>
```

selected bytes are read from that resolved commit tree.

This distinction is important for reproducibility: a branch-range context must represent the target revision even when the local working tree contains later or unrelated changes.

## Exclusions

A changed path can be excluded for deterministic reasons including:

```text
deleted
excluded_file_name
excluded_directory
too_large
binary
non_utf8
context_budget
symlink
not_regular_file
missing_at_source_revision
```

The content manifest records exclusions explicitly so missing provider coverage is not mistaken for reviewed code.

## Content binding

Each selected entry records:

```text
path
status
sources
previous_path
size_bytes
content_sha256
start_line
end_line
selection_reason
```

`content_sha256` binds the entry to the exact materialized bytes. The context also has a top-level `context_sha256` computed from the canonical content-free manifest.

The top-level digest therefore changes when any selected content hash, exclusion, source revision, scope, byte limit, or selection metadata changes.

The digest is a reproducibility identifier. It is not a claim that SHA-256 alone establishes source authenticity or supply-chain trust.

## Raw-content handling

`AdvisoryContext` contains the exact UTF-8 text internally so a provider can consume the bytes that were hashed.

The public JSON and Markdown renderers intentionally serialize only the content-free manifest. Raw source is not copied into the provenance artifact.

A typical manifest contains:

```text
mode
source_revision
from_ref / to_ref / commit
max_file_bytes
max_context_bytes
selected[]
excluded[]
total_selected_bytes
context_sha256
authority = ADVISORY_CONTEXT
gate_effect = NONE
```

## Runtime integrity checks

Before provider execution, the PR23 runtime now validates the context again.

Validation checks include:

- manifest digest integrity;
- selected/excluded path uniqueness and stable order;
- selected-file metadata versus materialized UTF-8 content;
- per-file SHA-256 and byte counts;
- line ranges;
- aggregate selected-byte count and budget;
- repository binding;
- branch/commit scope binding;
- per-file and aggregate byte-limit binding.

A malformed or mismatched context becomes a gate-neutral advisory source error. The provider is not called.

## OCR compatibility rule

OCR is a legacy external CLI that chooses its own native review set. It does not yet accept Before Deploy's materialized context files directly.

To avoid widening provider input, `OcrAdvisoryProvider` now compares OCR's deterministic Before Deploy preview set with the selected context set before invoking the OCR adapter.

OCR runs only when those sets are equal.

If context budgeting, encoding checks, or other context rules omit a path that OCR would otherwise consider, OCR is not started and the source reports:

```text
status = ERROR
scope_status = CONTEXT_LIMITED
findings = []
```

This failure remains advisory-only. It cannot change the deterministic `PolicyDecision`.

The existing OCR preflight/final-manifest scope attestation still runs after this context-compatibility check.

## Unified-review visibility

Successful provider results include a bounded context summary in advisory source metadata:

```text
context_sha256=<digest>
selected_files=<count>
selected_bytes=<used>/<budget>
excluded_files=<count>
```

PR25 will promote this into richer provider execution provenance rather than overloading advisory source metadata with execution attestations.

## Deliberate exclusions

PR24 does not add:

- semantic relevance ranking;
- model-generated file selection;
- embeddings or vector search;
- AST/function-level chunking;
- prompt construction;
- model/config identity;
- token or cost accounting;
- provider timing attestations;
- Evidence Graph nodes;
- any release authority for advisory context or provider findings.

Those remain later, separately reviewable increments.

## Trust boundary

```text
Git/workspace scope
       |
       v
review preview
       |
       v
Deterministic context selection
       |
       +--> exact materialized UTF-8 source
       +--> per-file hashes
       +--> aggregate byte budget
       +--> content-free context manifest
       |
       v
AdvisoryProvider runtime
       |
       v
provider findings
       |
       v
ADVISORY / gate_effect=NONE

-------------------------------- trust boundary

Deterministic controls -> policy -> PolicyDecision
```

The context selector constrains what an advisory provider may inspect. It does not make the provider authoritative.
