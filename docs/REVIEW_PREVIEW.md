# Deterministic Review Preview

## Purpose

`before-deploy review --preview` exposes the changed-file selection contract **before any advisory model or deterministic security control is executed**.

The preview is designed to make review coverage visible and reproducible. It answers:

- which changed files are in scope;
- which changed files are excluded;
- why a file is excluded;
- whether the scope comes from the workspace, a branch range, or a single commit.

This borrows the useful transparency idea from mature code-review systems while keeping the implementation and trust model independent.

## Usage

Workspace changes (staged, unstaged, and untracked):

```bash
uv run before-deploy review /path/to/repo --preview
```

Branch range using Git merge-base semantics:

```bash
uv run before-deploy review /path/to/repo \
  --preview \
  --from main \
  --to HEAD
```

Single commit:

```bash
uv run before-deploy review /path/to/repo \
  --preview \
  --commit abc123
```

The previous OCR-specific option names remain accepted as compatibility aliases:

```text
--ocr-from   -> --from
--ocr-to     -> --to
--ocr-commit -> --commit
```

## Non-execution guarantee

Preview mode does **not**:

- run the deterministic security scan;
- load waivers or evaluate release policy;
- invoke OpenCodeReview;
- send code to an LLM provider;
- import advisory files;
- produce a `PASS`, `BLOCK`, `WAIVER_REQUIRED`, or `ERROR` release decision.

It only inspects local Git state and local file metadata needed to describe review selection.

## Modes

### WORKSPACE

The preview combines:

- unstaged tracked changes;
- staged tracked changes;
- untracked files not ignored by Git.

A file may therefore expose more than one source, for example:

```text
sources = [STAGED, WORKTREE]
```

### RANGE

`--from A --to B` uses the Git three-dot range:

```text
A...B
```

This represents changes from the merge base of the two refs to the target ref.

### COMMIT

`--commit X` previews the paths changed by that commit relative to its first parent. Root commits use Git's root-diff behavior.

## Exclusion reasons

Review preview reuses the canonical repository exclusion policy used by the deterministic inventory rather than maintaining a separate list.

Current reasons include:

| Reason | Meaning |
|---|---|
| `deleted` | The changed path no longer exists and cannot be reviewed as a current file. |
| `excluded_directory` | The path is under a generated/cache/vendor-style directory excluded by repository inventory. |
| `excluded_file_name` | The file name is explicitly excluded by repository inventory. |
| `too_large` | The current file exceeds `--max-file-bytes`. |
| `not_regular_file` | The current path is not a regular file. |
| `unreadable` | File metadata could not be inspected safely. |

These reasons describe **selection only**. They are not security findings and have no gate effect.

## Outputs

Preview mode writes:

- `preview.json`
- `preview.md`

The JSON contains a stable schema with:

- mode;
- repository path;
- range/commit metadata when applicable;
- total changed-file count;
- reviewable count;
- excluded count;
- per-file status;
- per-file source (`STAGED`, `WORKTREE`, `UNTRACKED`, or `GIT`);
- inclusion decision;
- exclusion reason;
- previous path for detected renames/copies.

## Relationship to OCR and future providers

The preview is provider-independent. OCR remains an advisory integration and does not gain release authority.

The intended long-term architecture is:

```text
Git state / explicit range
          |
          v
Deterministic review selection
          |
          +----> preview.json / preview.md
          |
          v
Advisory provider(s)
          |
          v
ADVISORY findings
          |
          v
Unified review

---------------- trust boundary ----------------

Deterministic security controls
          |
          v
PolicyDecision
```

A future provider-routing increment can require advisory engines to consume this selection contract rather than independently deciding what to inspect.
