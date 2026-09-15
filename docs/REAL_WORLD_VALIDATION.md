# Independent real-world validation

This document specifies how Before Deploy produces the evidence required by section 3 of
`docs/PRODUCTION_READINESS_CRITERIA.md`. The harness lives in
`src/before_deploy/real_world_validation.py`.

Everything here is `BENCHMARK_DIAGNOSTIC` evidence with `gate_effect=NONE`. It never grants
advisory findings release authority and never changes release disposition.

## What section 3 requires

A blinded benchmark over frozen pre-fix snapshots from at least **3 unrelated public
repositories** containing at least **6 independently documented historical defects**, where:

- exploratory known-defect recall is at least `0.60`;
- exploration-attributable true positives are strictly greater than exploration-attributable
  false positives;
- the exploratory false-positive rate does not exceed the static baseline rate;
- every credited finding cites evidence supplied in that run;
- no benchmark-label leakage reaches the reviewer, and no expected location is disclosed.

## Frozen measurement definitions

- **Known-defect recall** is the number of distinct frozen corpus defect IDs credited by the
  exploratory variant divided by the number of frozen corpus defects, across all repositories.
- **False-positive rate** is that variant's unmatched finding count divided by the number of
  reviewed files in the frozen corpora, that is the total of `positive` and `negative` files
  declared by the per-repository provenance manifests. Both variants review the same files, so
  the two rates are directly comparable. The per-file denominator is used deliberately: the
  snapshot sets are recall-oriented and do not attempt to sample a representative negative
  population, so a "per true negative" rate would be unmeasurable.
- **Credit** means a matched defect. A credited finding must additionally have a supported claim
  and a citation to an evidence ID supplied in that run; otherwise the run records
  `uncited_credit_count` and fails closed.

## Corpus layout and population

Each repository contributes four artifacts under
`fixtures/real-world-validation/<bucket>/`:

| Artifact | Purpose |
|---|---|
| `corpus.json` | the labeled defect corpus, in the frozen `review_benchmark` schema |
| `manifest.json` | the existing corpus provenance manifest, validated by `review_benchmark_corpus` |
| `NOTICE` | the upstream license and attribution notice for the vendored snapshot |
| `src/**` | the frozen pre-fix source snapshot |

The validation manifest lists one entry per repository:

```json
{
  "schema_version": "before-deploy-real-world-validation-v1",
  "validation": {
    "name": "real-world-seed",
    "repositories": [
      {
        "repository_id": "RW-3F7A",
        "repository": "https://github.com/owner/project",
        "commit": "0000000000000000000000000000000000000000",
        "corpus": "fixtures/real-world-validation/<bucket>/corpus.json",
        "provenance": "fixtures/real-world-validation/<bucket>/manifest.json",
        "license_notice": "fixtures/real-world-validation/<bucket>/NOTICE"
      }
    ]
  }
}
```

Population rules:

1. Snapshot the file(s) at the **pre-fix** revision of the documented defect. The `commit` field
   is the full 40-character Git SHA of the local snapshot commit that contains the vendored
   snapshot, exactly as the existing corpus provenance contract requires.
2. Give every repository an opaque `repository_id` matching `[A-Z]{2}-[0-9A-Z]{4}` and every
   defect an opaque ID matching `[A-Z]{1,3}-[0-9A-Z]{3,}`. Advisory-style IDs such as
   `CVE-2021-44228` are rejected because they disclose the defect. Record advisory references,
   fix commits, and rationale only in evaluator-only metadata.
3. Declare distinct repositories and distinct snapshot commits. Duplicate IDs, duplicate
   repositories, duplicate commits, and defect IDs reused across repositories are rejected.
4. Label each defect with the canonical advisory category and severity vocabulary, a root-cause
   rationale, and an `evidence_test` selector that exists in this repository, per
   `docs/REVIEW_BENCHMARK_LABELING.md`.
5. Vendor only the snapshot bytes needed to reproduce the review. Keep the upstream license
   notice with the snapshot; the validator fails closed when a notice is missing.
6. Review each repository as a whole file. The provider must receive the full frozen file, not a
   range narrowed to the defect, otherwise the expected location is disclosed.

## Blinding

`REVIEW_BENCHMARK_LABELING.md` defines the evaluator/provider separation. This harness adds one
mechanical runtime check that the runner must apply to every provider payload:

```python
assert_model_visible_payload_is_blinded(payload, forbidden_tokens=(...))
```

It fails closed when a payload contains an evaluator-only token the caller supplies (advisory
identifier, fix commit, expected location, label text, repository name), when it matches a
CVE/GHSA/advisory-URL pattern, or when it exposes any key outside the model-visible allowlist
(`evidence_id`, `path`, `content`, `content_sha256`, `source_start_line`, `source_end_line`).
A run that fails this check is contaminated and must not be reported as a §3 result.

## Applying the result

Validate the pinned corpora, then evaluate a recorded paired run:

```bash
before-deploy-real-world-validation --manifest fixtures/real-world-validation/validation.json
before-deploy-real-world-validation \
  --manifest fixtures/real-world-validation/validation.json \
  --run reports/real-world-validation/run.json \
  --output-dir reports/real-world-validation
```

Exit codes are `0` (all §3 criteria passed), `1` (criteria not met), and `2` (input error), so a
readiness job fails closed on more than a formatting problem. The run record is a small paired
observation file:

```json
{
  "schema_version": "before-deploy-real-world-run-v1",
  "static": {"detected_defect_ids": [], "false_positive_count": 0},
  "exploratory": {
    "detected_defect_ids": ["D-0001", "D-0003"],
    "exploration_attributable_tp": 2,
    "exploration_attributable_fp": 0,
    "false_positive_count": 0,
    "uncited_credit_count": 0
  }
}
```

Unknown fields are rejected so evaluator-only data cannot be smuggled into a run record.

Programmatically the same path is available, and readiness evidence must be populated from the
projection rather than written by hand:

```python
definition = validate_real_world_benchmark(manifest_path, repository_root)
result = evaluate_real_world_validation(definition, static=..., exploratory=...)
evidence_fields = real_world_readiness_evidence(result)
```

> **Commit requirement.** The reused corpus provenance contract verifies each snapshot blob with
> `git ls-tree` at the declared snapshot commit, so it requires that commit to exist in local Git
> history. Vendored snapshots therefore cannot validate until they are committed. Validate after
> committing the fixtures, not before.

`real_world_readiness_evidence` projects the result onto the nine `real_world_*` fields of
`ProductionReadinessEvidence`. Readiness evidence must be populated from that projection rather
than written by hand, so the frozen readiness gate reads measured facts instead of assertions.

`render_real_world_validated_json` and `render_real_world_validated_markdown` produce the
retained artifact. Retain it with the run ID and content digest alongside the production-readiness
evidence.

## What this harness does not enforce

- **Unrelatedness beyond identity.** The harness enforces distinct repository URLs, distinct
  snapshot commits, and globally unique defect IDs. It cannot detect three URLs that are forks,
  mirrors, or snapshots of one upstream project. Unrelatedness remains a reviewed judgement that
  must be recorded in the corpus rationale.
- **Whole-file review coverage.** Rule 6 above is a corpus-authoring rule enforced by review; it
  is not mechanically verified against the runner's actual payload.
- **Defect documentation authenticity.** "Independently documented" means the defect has a public
  upstream record. The harness checks label provenance and the cited regression test, not the
  existence or independence of that upstream record.
- **Historical fix attribution.** The harness pins a pre-fix snapshot by commit and blob. It does
  not verify that a later upstream revision fixes the defect.

## Seed corpus v1

`fixtures/real-world-validation` contains three unrelated repositories with two independently
documented historical defects each. Every pin below was established by fetching both revisions of
the affected file from `raw.githubusercontent.com` and diffing them; the hunks that moved are the
labeled defects.

| Bucket | Repository | License | Pre-fix | Fixed | Vendored file | Label |
|---|---|---|---|---|---|---|
| `rw-3f7a` | `aio-libs/aiohttp` | Apache-2.0 | `v3.9.1` | `v3.9.2` | `pkg/web_urldispatcher.py` | `D-0101` |
| `rw-3f7a` | `aio-libs/aiohttp` | Apache-2.0 | `v3.9.1` | `v3.9.2` | `pkg/http_parser.py` | `D-0102` |
| `rw-9k2m` | `pallets/werkzeug` | BSD-3-Clause | `3.0.5` | `3.0.6` | `pkg/security.py` | `D-0201` |
| `rw-9k2m` | `pallets/werkzeug` | BSD-3-Clause | `3.0.5` | `3.0.6` | `pkg/formparser.py` | `D-0202` |
| `rw-5p8q` | `django/django` | BSD-3-Clause | `5.0.6` | `5.0.7` | `pkg/base.py` | `D-0301` |
| `rw-5p8q` | `django/django` | BSD-3-Clause | `5.0.6` | `5.0.7` | `pkg/html.py` | `D-0302` |

Each defect is a missing or misplaced guard rather than a synthetic pattern: a containment check
that ran only on one branch of a symlink flag, a header-name check ordered after an index
operation, an absolute-path rejection that did not cover one separator form, a per-field size
budget that was never accumulated, a name validation that ran only after the write, and a
per-character rescan that was never memoized. Every label is anchored to the narrowest vulnerable
line range in the pre-fix file, and its paired `secure/` file carries the upstream fix.

### Vendoring decisions

- **Neutral model-visible paths.** Each vendored package directory is renamed to `pkg` so the
  upstream project identity does not appear in the paths a reviewer sees. The upstream path for
  each snapshot lives in the evaluator-only `rationale` field. This is a deliberate trade of
  snapshot-path fidelity for blinding; file basenames are preserved because they are part of what
  a reviewer reasons about.
- **Byte stability.** `.gitattributes` marks the whole of `fixtures/**` as non-text. With
  `core.autocrlf=true` a line-ending conversion on checkout would rewrite the snapshots and
  invalidate every pinned blob SHA-1, and the same conversion silently disabled
  `SEC-GO-VULN-001` by corrupting the packaged snapshot's pinned digest. The repo-wide invariant,
  the artifacts it covers, and the recovery steps are in
  [CHECKOUT_BYTE_INTEGRITY.md](CHECKOUT_BYTE_INTEGRITY.md), guarded by
  `tests/unit/test_checkout_byte_integrity.py`.
- **License records.** `LICENSE.upstream` in each bucket is the verbatim upstream license at the
  fixed revision, and `NOTICE` records the source, revision, and the fact that the snapshots are
  unmodified. Neither file is review input, so neither is declared in `manifest.json.files`.
- **Evidence-test form.** Every label cites a test in
  `tests/unit/test_real_world_fixture_provenance.py`. Those tests pin the labeled root cause to the
  vendored bytes and confirm the paired fixed revision changed exactly that construct. They do not
  execute the snapshot or assert a Before Deploy control finding, because these snapshots are
  third-party modules whose upstream dependencies are not installed in this repository. They are
  drift checks that fail the deterministic suite when a snapshot or a label moves.

### Completing the pin

The three `manifest.json` files and `validation.json` currently carry an all-zero
`source_snapshot.commit`. The reused provenance contract resolves each snapshot with
`git ls-tree` at that commit, so the value cannot exist until the snapshots are committed:

```bash
git add fixtures/real-world-validation .gitattributes
git commit -m "test: vendor real-world validation snapshots"
# then set source_snapshot.commit in the three manifests and commit in validation.json
# to the commit that introduced the snapshots, and re-run:
before-deploy-real-world-validation --manifest fixtures/real-world-validation/validation.json
```

Until that pin is filled the validator fails closed with "snapshot commit is unavailable in local
Git history". Blob-hash validation already passes for all twelve vendored files.

## Status

The section 3 corpora now exist, but no blinded run over them has been executed and the snapshot
commit is not yet pinned, so section 3 remains unproven and Before Deploy remains
`PRODUCTION_CANDIDATE`. Until a run passes, the readiness gate still reports
`INSUFFICIENT_REAL_WORLD_*` reasons, which is the intended fail-closed behavior.
