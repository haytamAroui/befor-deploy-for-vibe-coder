# Native Agent Repository Tools

PR42 adds the deterministic mediation layer between AI curiosity and repository evidence.

The model never receives a generic shell, subprocess, file-write, patch, Git mutation, approval, verification, or release tool. The allow-list is limited to read-only observations:

```text
read_file
search_text
search_symbol
find_references
find_callers
find_tests
dependency_neighbors
```

## Repository index

`RepositoryIndex` starts from the canonical Before Deploy inventory contract, then applies additional agent-specific bounds for indexed files and total indexed bytes. Only UTF-8 regular repository files are indexed; symlinked paths are excluded.

The index records line-oriented source, lightweight multi-language symbol definitions, import/dependency tokens, lexical references, and test-path classification. Call/reference/dependency results are explicitly static lexical evidence, not runtime reachability or full interprocedural proof.

## Dynamic context expansion

The initial changed-file context remains the starting envelope. `RepositoryToolPolicy.allow_scope_expansion` determines whether a run may inspect other files from the same bounded repository index.

When expansion is disabled, reads and discovery are limited to the starting paths. When enabled, the model may request additional indexed evidence, but Before Deploy still mediates the request and records the exact hashed tool result in the agent run.

## Path policy

Every explicit file path must be canonical repository-relative text. Absolute paths, parent traversal, drive paths, non-indexed files, and symlinked path components are rejected.

## Result bounds

Tool results are canonical JSON. Each result is SHA-256 content-addressed by the PR41 runtime. If a result would exceed the per-tool byte budget, raw result content is replaced by bounded truncation metadata containing the original digest and size.

No result can grant release authority. Repository-tool observations are evidence available to an advisory agent only.
