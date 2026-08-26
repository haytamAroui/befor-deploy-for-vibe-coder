# Release Evidence Operations

This guide describes the **current operating model** for release evidence. It separates what can run now in the repository from the GitHub-attestation workflow that must remain a template until private-repository eligibility is confirmed.

> **Important:** GitHub documents artifact attestations as available on all plans for public repositories, while private/internal repositories require GitHub Enterprise Cloud. This repository is private. Do not activate the template workflow until the repository owner has verified eligibility. [1]

## 1. Calibrate external security scanners

The active workflow `.github/workflows/external-scanner-calibration.yml` is manual-only. It installs the reviewed Gitleaks release archive after SHA-256 verification, installs the pinned Semgrep version, and runs `external-adapters-policy.yaml` against the repository.

Run it from the repository’s **Actions** page using **External scanner calibration → Run workflow**. The workflow uses read-only repository permissions, does not receive pull-request write permissions, and retains only redacted reports for 14 days.

A successful calibration establishes that the pinned Gitleaks/Semgrep binaries, local rule configuration, and Before Deploy adapters work together in the GitHub-hosted runner. It does not make those tools an unquestioned release authority; any rule/profile changes still require fixture-based review.

## 2. Create local release evidence

Use a clean checkout at the intended release commit. The preparation script uses only Git-tracked regular files, does not execute project code, produces a stable `tar.gz` archive, writes a SHA-256 checksum, and derives a CycloneDX 1.5 document from `uv.lock`.

```bash
source_date_epoch="$(git log -1 --format=%ct)"
uv run python scripts/prepare_release_evidence.py \
  --repository . \
  --output-dir dist \
  --source-date-epoch "$source_date_epoch"
```

For the current project version, this produces:

| Evidence | Expected location |
|---|---|
| Source-release artifact | `dist/before-deploy-0.1.0.tar.gz` |
| SHA-256 checksum | `dist/before-deploy-0.1.0.sha256` |
| CycloneDX SBOM | `dist/before-deploy-0.1.0.cdx.json` |

The script emits a JSON summary with the artifact SHA-256 value. Store the three files together as release evidence. Do not edit the artifact or SBOM after calculating/attesting it.

## 3. Enable GitHub attestation only after eligibility confirmation

The non-active template at `docs/release-attestation-workflow.yml.example` creates both a build-provenance attestation and an SBOM attestation with `actions/attest`. Before enabling it, perform each action below through a reviewed pull request:

1. Confirm GitHub Enterprise Cloud eligibility for this private repository, or intentionally change the release hosting/repository arrangement.
2. Copy the template to `.github/workflows/release.yml`; do not simply delete the warning comment in place.
3. Confirm the project version and artifact file names in both the workflow and `rules/release-evidence-policy.yaml`.
4. Keep the workflow restricted to trusted tag pushes. Do not run it on pull-request-controlled source.
5. Preserve the permissions exactly scoped to `contents: read`, `id-token: write`, and `attestations: write`; do not add broad write permissions.
6. Execute a controlled test tag and inspect the GitHub attestation summary before treating the output as release evidence.

The template retains the source artifact, SBOM, checksum, and runner-local attestation bundles as a workflow artifact. GitHub’s attestation action also associates the signed record with the repository. [1]

## 4. Prepare offline provenance verification input

Once a provenance attestation exists, obtain the bundle using the GitHub CLI from an online machine:

```bash
mkdir -p attestations
gh attestation download dist/before-deploy-0.1.0.tar.gz \
  --repo haytamAroui/befor-deploy-for-vibe-coder
mv sha256:*.jsonl attestations/before-deploy.intoto.jsonl
```

For an air-gapped verification environment, additionally export a fresh trusted root:

```bash
gh attestation trusted-root > attestations/trusted_root.jsonl
```

GitHub documents using the downloaded bundle and trusted root with `gh attestation verify` for offline verification. [2] The current Before Deploy provenance adapter verifies the local bundle and local artifact with the expected repository, signer workflow, SLSA provenance predicate, and hosted-runner restriction. It intentionally does not inspect workflow-controlled predicate metadata as an independently trusted signal.

## 5. Run the release-evidence gate

Place the artifact, SBOM, and provenance bundle at the paths declared in `rules/release-evidence-policy.yaml`, ensure `uv`, `pip-audit`, and `gh` versions match policy, then run:

```bash
uv run before-deploy scan . \
  --policy rules/release-evidence-policy.yaml \
  --output-dir reports/release-evidence
```

The gate returns `0` only when every required control completes and no blocking finding remains. Any missing scanner, absent lock/SBOM/artifact/bundle, invalid vulnerability report, or failed provenance verification produces exit code `20`. A known dependency advisory produces a normalized finding and is governed by the release policy disposition.

## References

[1]: https://github.com/actions/attest "actions/attest: permissions, outputs, and private-repository availability"
[2]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline "GitHub documentation: offline attestation bundle and trusted-root verification"
