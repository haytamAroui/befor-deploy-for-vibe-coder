# Dependency and Provenance Research Notes

**Captured:** 27 August 2026  
**Purpose:** Authoritative technical constraints for the dependency-vulnerability and provenance adapters.

## pip-audit

The [pip-audit README](https://github.com/pypa/pip-audit) documents that the tool audits Python environments, requirements-style inputs, and local project dependency trees for known vulnerabilities. Its supported output includes JSON, and its documented completion codes are `0` for no known vulnerabilities and `1` when one or more known vulnerabilities are found. The exit status cannot be internally suppressed, so an adapter must interpret a valid report together with its process outcome.

For a local Python project, `pip-audit --locked <project-path>` audits lockfiles. pip-audit documents `--strict` as failing the audit when dependency collection fails. It supports `--format json`, `--output <file>`, `--timeout <seconds>`, a selectable vulnerability service, and `--no-deps` only when requirements are fully pinned. Its JSON examples represent dependencies as records with a package `name`, `version`, and `vulns` array. A vulnerability record includes at least an `id` and may include `fix_versions`, `aliases`, and an explanatory `description`.

The pip-audit security model cautions that it detects known vulnerabilities in dependencies, is not a static analyzer, and must not be treated as protection against malicious packages. Dependency collection/audit failure must be explicit.

**Adapter implication:** Run only a fixed command against the repository root, use `--locked --format json --output <temporary-path> --strict`, retain no raw tool logs, normalize package/version/vulnerability ID/fix-version evidence, treat valid exit code `1` plus valid JSON findings as a completed scan, and treat any collection/error/invalid-report case as `ERROR`.

## GitHub artifact attestations and provenance verification

The [GitHub CLI `gh attestation verify` manual](https://cli.github.com/manual/gh_attestation_verify) states that the command verifies artifact integrity and provenance through cryptographically signed attestations. Verification requires an artifact path or an `oci://` image URI plus at least an expected `--owner` or `--repo`. The default predicate type is `https://slsa.dev/provenance/v1`.

For stronger identity enforcement, the CLI supports `--signer-workflow`, `--signer-repo`, `--cert-identity`, `--source-ref`, `--source-digest`, and `--deny-self-hosted-runners`. Successful `--format json` output includes a signed certificate representation and verified timestamps; the manual explicitly warns that `statement.predicate` contains metadata potentially controlled by the originating workflow and must not be used as an independently trusted field.

GitHub’s [artifact-attestations documentation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) describes generation of build provenance with `actions/attest`, using `id-token: write`, `contents: read`, and `attestations: write` permissions. The same documentation gives `gh attestation verify <artifact> -R owner/repo` as the basic binary-verification command and shows explicit predicate types for SBOM attestations.

The [SLSA provenance specification](https://slsa.dev/spec/v1.0/provenance) defines provenance as verifiable information describing where, when, and how an artifact was produced; it identifies `https://slsa.dev/provenance/v1` as the predicate type. The retrieved v1.0 page is marked retired in favor of SLSA v1.2, so the adapter must use the predicate string GitHub CLI verifies rather than claim a generic SLSA level.

**Adapter implication:** Build a local artifact-verification adapter around a fixed `gh attestation verify` argument list. Require the artifact to exist; require an expected repository and signer workflow identity in policy; use `--predicate-type https://slsa.dev/provenance/v1`, `--format json`, `--deny-self-hosted-runners`, and a temporary output file. Trust only process success and the CLI’s verified certificate/timestamp result. Do not infer security guarantees from workflow-controlled predicate metadata. Missing `gh`, verification failure, invalid output, or identity mismatch must yield `ERROR`.
