"""Guard the checkout byte-integrity of every content-pinned repository artifact.

Several artifacts in this repository are verified by exact content rather than by
parsing: the packaged offline Go vulnerability snapshot carries a pinned SHA-256,
and each benchmark corpus manifest pins its source files by Git blob SHA-1. Those
checks read working-tree bytes.

Git EOL conversion is therefore a correctness threat to them, not a formatting
preference. With ``core.autocrlf=true`` -- the default on Windows Git installs --
a checkout rewrites these files to CRLF, the pinned digests stop matching, and the
affected controls fail closed. A converted working tree also produces a converted
wheel, so the package would ship a snapshot that fails its own integrity check.

This module asserts the two facts that keep that from recurring:

1. Git reports every pinned path as ``text: unset`` (i.e. covered by a ``-text``
   rule in ``.gitattributes``), so no EOL conversion applies to it.
2. The bytes actually on disk hash to the pinned digest.

Both are property checks over the pins the code already declares, so a newly added
pinned artifact is covered as soon as it is registered -- there is no second list
of paths to keep in sync.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from before_deploy.controls.go_vulnerabilities import (
    BUILTIN_SNAPSHOT_PATH,
    BUILTIN_SNAPSHOT_SHA256,
)
from before_deploy.review_benchmark_corpus import git_blob_sha1

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES_ROOT = PROJECT_ROOT / "fixtures"

LINE_ENDING_HINT = (
    "Git EOL conversion rewrote a content-pinned file. A '-text' rule in .gitattributes must "
    "cover this path, and the file must then be re-materialized from the index (delete it and "
    "run `git checkout -- <path>`) so the working tree holds the committed bytes again. "
    "Do not use `git reset --hard` here: it would also discard unrelated uncommitted work."
)


def _run_git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
    )


def _pinned_manifest_files() -> Iterator[tuple[str, str, str]]:
    """Yield ``(manifest, relative path, pinned git blob sha1)`` for every corpus manifest."""
    for manifest_path in sorted(FIXTURES_ROOT.rglob("manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw_files = manifest.get("files")
        if not isinstance(raw_files, list):
            continue
        relative = manifest_path.relative_to(PROJECT_ROOT).as_posix()
        for entry in raw_files:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            digest = entry.get("git_blob_sha1")
            if isinstance(path, str) and isinstance(digest, str):
                yield relative, path, digest


def _sha256_hex(content: bytes) -> str:
    return sha256(content).hexdigest()


@dataclass(frozen=True)
class PinnedArtifact:
    """One file whose exact bytes some verifier checks, plus that verifier's expectation."""

    path: str
    label: str
    expected: str
    digest: Callable[[bytes], str]


def _pinned_artifacts() -> list[PinnedArtifact]:
    """Discover every content-pinned artifact from the pins the code already declares."""
    artifacts = [
        PinnedArtifact(
            path=BUILTIN_SNAPSHOT_PATH.relative_to(PROJECT_ROOT).as_posix(),
            label="packaged_offline_go_vulnerability_snapshot",
            expected=BUILTIN_SNAPSHOT_SHA256,
            digest=_sha256_hex,
        )
    ]
    seen = {artifact.path for artifact in artifacts}
    for manifest, path, expected in _pinned_manifest_files():
        if path in seen:
            continue
        seen.add(path)
        artifacts.append(
            PinnedArtifact(
                path=path,
                label=manifest,
                expected=expected,
                digest=git_blob_sha1,
            )
        )
    return artifacts


def _check_attr_text(paths: list[str]) -> dict[str, str]:
    result = _run_git("check-attr", "-z", "text", "--", *paths)
    if result.returncode != 0:
        pytest.skip("git check-attr is unavailable in this checkout")
    fields = result.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    resolved: dict[str, str] = {}
    for index in range(0, len(fields) - 2, 3):
        resolved[fields[index].decode("utf-8")] = fields[index + 2].decode("utf-8")
    return resolved


def test_pinned_artifacts_are_registered() -> None:
    """The pin registries this guard reads must be non-empty, or it silently proves nothing."""
    artifacts = _pinned_artifacts()
    assert artifacts, "no content-pinned artifacts were discovered"
    assert any(artifact.digest is _sha256_hex for artifact in artifacts)
    assert any(artifact.digest is git_blob_sha1 for artifact in artifacts)


def test_git_never_converts_a_pinned_artifact() -> None:
    """Every content-pinned path must be excluded from EOL conversion."""
    artifacts = _pinned_artifacts()
    attributes = _check_attr_text([artifact.path for artifact in artifacts])

    converted = sorted(
        f"{artifact.path} (pinned by {artifact.label})"
        for artifact in artifacts
        if attributes.get(artifact.path) != "unset"
    )
    assert converted == [], (
        f"content-pinned artifacts are subject to EOL conversion: {converted}. "
        f"{LINE_ENDING_HINT}"
    )


def test_pinned_artifacts_match_their_pinned_bytes() -> None:
    """The bytes on disk must hash to the digest each verifier was given."""
    mismatched: list[str] = []

    for artifact in sorted(_pinned_artifacts(), key=lambda item: item.path):
        raw = (PROJECT_ROOT / artifact.path).read_bytes()
        actual = artifact.digest(raw)
        if actual != artifact.expected:
            mismatched.append(
                f"{artifact.path}: {len(raw)} bytes, "
                f"expected {artifact.expected}, got {actual}"
            )

    assert mismatched == [], f"pinned artifact drift: {mismatched}. {LINE_ENDING_HINT}"
