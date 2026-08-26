# Release Workflow Research Notes

**Captured:** 27 August 2026  
**Purpose:** Constraints for generating and consuming release artifacts, SBOMs, and GitHub artifact attestations.

## Verified facts

The official [actions/attest documentation](https://github.com/actions/attest) states that `actions/attest` creates signed in-toto attestations using a short-lived Sigstore-issued certificate and uploads them to the GitHub Attestations API. For a file artifact, the workflow must have at least `id-token: write`, `contents: read`, and `attestations: write`; SBOM attestation passes `sbom-path` together with the artifact subject path. The action records the created bundle path on the runner and exposes a `bundle-path` output.

The same documentation states that artifact attestations are available on all GitHub plans for **public repositories**, but use in **private or internal repositories requires GitHub Enterprise Cloud**. This repository is private, so a runnable attestation job must not be enabled until its owner verifies the required GitHub plan or makes an intentional repository/hosting decision.

GitHub’s [offline-verification guide](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline) documents downloading an attestation bundle through `gh attestation download <artifact> -R owner/repository`, exporting trusted roots with `gh attestation trusted-root`, and using `gh attestation verify <artifact> -R owner/repository --bundle <bundle> --custom-trusted-root <trusted-root>` in an offline environment.

## Design consequence

This milestone may safely ship deterministic local artifact/SBOM preparation scripts and a pinned scanner-calibration CI workflow. It should provide the GitHub release-attestation workflow as a **non-active template** plus documentation rather than enable a production attestation workflow that is expected to fail for a private repository lacking confirmed Enterprise Cloud eligibility.

The release-evidence policy remains valuable: it verifies an artifact plus a downloaded bundle supplied by a trusted build system. It is deliberately independent of whether this repository itself can generate GitHub-hosted attestations today.

## References

[1]: https://github.com/actions/attest "actions/attest README: permissions, outputs, attestation modes, and private-repository availability"
[2]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline "GitHub documentation: download, trusted-root export, and offline bundle verification"
[3]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds "GitHub documentation: build and SBOM attestation workflow requirements"
