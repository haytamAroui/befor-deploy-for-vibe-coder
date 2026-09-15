# Checkout byte integrity

Some artifacts in this repository are verified by **exact content** rather than by parsing. A
line-ending conversion during checkout rewrites the very bytes those checks verify, so the checks
fail closed. This document records the invariant, the artifacts it covers, and what to do when it
breaks.

## The invariant

Every file whose exact bytes a verifier checks must be committed and checked out **untouched**, on
every platform. `.gitattributes` marks those trees as non-text, which disables Git's EOL
conversion for them.

## Covered artifacts

| Artifact | Verifier | Pinned by |
| --- | --- | --- |
| `src/before_deploy/controls/data/go_vulnerability_snapshot.json` | `GoVulnerabilitySnapshotControl` | `BUILTIN_SNAPSHOT_SHA256` (SHA-256 of the file) |
| Every file declared in a `fixtures/**/manifest.json` `files[]` entry | `validate_benchmark_corpus_provenance`, `validate_real_world_benchmark` | `git_blob_sha1` (Git blob SHA-1) |

`tests/unit/test_checkout_byte_integrity.py` discovers this list from the pins the code already
declares, so a newly pinned artifact is covered as soon as it is registered. There is no second
list of paths to keep in sync.

## Why this is a correctness guard, not formatting

The failure is not cosmetic and it is not confined to tests:

- `GoVulnerabilitySnapshotControl` hashes the packaged snapshot before reading it. A converted file
  fails `SNAPSHOT_DIGEST_MISMATCH`, so the control reports `ERROR` and `SEC-GO-VULN-001` produces
  **no findings at all**.
- A package built from a converted working tree contains converted bytes, so the wheel would ship a
  snapshot that fails its own integrity check.
- Corpus manifests pin their sources by blob SHA-1. Conversion makes every pinned digest stop
  matching, so the corpus fails provenance validation and the readiness gates that depend on it
  cannot pass.

Failing closed is the correct behavior. The defect is that the repository previously permitted the
conversion in the first place.

## Adding a byte-pinned artifact

1. Register the pin where the verifier reads it (a manifest `files[]` entry, or a digest constant
   beside the file).
2. Make sure the path is covered by a `-text` rule in `.gitattributes`. Add a rule if the artifact
   lives outside `fixtures/**` and `src/before_deploy/controls/data/**`.
3. Run `python -m pytest tests/unit/test_checkout_byte_integrity.py`. It reports which paths are
   unconverted-but-convertible and which pins no longer match.

## Recovering a converted checkout

After adding a missing `-text` rule, the files on disk are still converted until they are
re-materialized from the index. For each path reported by the guard:

```bash
rm -f <path> && git checkout -- <path>
```

Do **not** reach for `git reset --hard`: it would also discard unrelated uncommitted work. On
Windows, `core.autocrlf=true` is the usual cause; the `-text` rules take precedence over it, so no
per-clone configuration change is required.
