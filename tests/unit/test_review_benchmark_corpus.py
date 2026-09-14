from __future__ import annotations

from json import dumps, loads
from pathlib import Path
from subprocess import run

import pytest

from before_deploy.review_benchmark import evaluate_advisory_output
from before_deploy.review_benchmark_corpus import (
    git_blob_sha1,
    validate_benchmark_corpus_provenance,
)

ROOT = Path(__file__).parents[2]
CORPUS = ROOT / "fixtures" / "review-benchmark-v1" / "corpus.json"
MANIFEST = ROOT / "fixtures" / "review-benchmark-v1" / "manifest.json"
ORACLE = ROOT / "fixtures" / "review-benchmark-v1" / "oracle-advisory.json"


def _git(repository: Path, *arguments: str) -> str:
    completed = run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def test_seed_corpus_provenance_and_oracle_are_consistent():
    validation = validate_benchmark_corpus_provenance(CORPUS, MANIFEST, ROOT)

    assert validation.name == "before-deploy-security-seed-v1"
    assert validation.defect_count == 4
    assert validation.positive_file_count == 4
    assert validation.negative_file_count == 4
    assert validation.source_commit == "d9e0b9d15178e98e5a261bcc26b26bd589af823f"

    result = evaluate_advisory_output(CORPUS, ORACLE)
    assert result.true_positives == 4
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0
    assert {item.category for item in result.category_metrics} == {"security"}
    assert result.gate_effect == "NONE"


def test_seed_manifest_contains_paired_positive_and_negative_sources():
    payload = loads(MANIFEST.read_text(encoding="utf-8"))
    roles = [item["role"] for item in payload["files"]]
    source_paths = {item["path"] for item in payload["files"]}
    defect_paths = {
        item["path"]
        for item in loads(CORPUS.read_text(encoding="utf-8"))["benchmark"]["defects"]
    }

    assert roles.count("positive") == 4
    assert roles.count("negative") == 4
    assert defect_paths < source_paths
    assert all(item["category"] == "security" for item in payload["labels"])


def test_seed_manifest_rejects_source_byte_drift(tmp_path):
    payload = loads(MANIFEST.read_text(encoding="utf-8"))
    payload["files"][0]["git_blob_sha1"] = "0" * 40
    broken_manifest = tmp_path / "manifest.json"
    broken_manifest.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Git blob hash mismatch"):
        validate_benchmark_corpus_provenance(CORPUS, broken_manifest, ROOT)


def test_seed_manifest_rejects_label_provenance_drift(tmp_path):
    payload = loads(MANIFEST.read_text(encoding="utf-8"))
    payload["labels"][0]["start_line"] = 10
    broken_manifest = tmp_path / "manifest.json"
    broken_manifest.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match corpus defect"):
        validate_benchmark_corpus_provenance(CORPUS, broken_manifest, ROOT)


def test_seed_manifest_rejects_missing_evidence_test_selector(tmp_path):
    payload = loads(MANIFEST.read_text(encoding="utf-8"))
    payload["labels"][0]["evidence_test"] = (
        "tests/integration/test_scan_fixtures.py::test_not_a_real_regression"
    )
    broken_manifest = tmp_path / "manifest.json"
    broken_manifest.write_text(dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="selector does not exist"):
        validate_benchmark_corpus_provenance(CORPUS, broken_manifest, ROOT)


def test_manifest_rejects_valid_snapshot_commit_with_different_source_blob(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Before Deploy Tests")
    _git(repository, "config", "user.email", "tests@before-deploy.invalid")

    source = repository / "src" / "example.py"
    source.parent.mkdir()
    source.write_text("old vulnerable shape\n", encoding="utf-8")
    _git(repository, "add", "src/example.py")
    _git(repository, "commit", "-m", "seed historical source")
    source_commit = _git(repository, "rev-parse", "HEAD")

    source.write_text("current vulnerable shape\n", encoding="utf-8")
    (repository / "docs").mkdir()
    (repository / "docs" / "labels.md").write_text("# Labels\n", encoding="utf-8")
    (repository / "tests").mkdir()
    (repository / "tests" / "test_example.py").write_text(
        "def test_expected_issue():\n    pass\n",
        encoding="utf-8",
    )

    corpus = repository / "corpus.json"
    corpus.write_text(
        dumps(
            {
                "schema_version": 1,
                "benchmark": {
                    "name": "snapshot-mismatch",
                    "defects": [
                        {
                            "id": "SEC-1",
                            "path": "src/example.py",
                            "start_line": 1,
                            "end_line": 1,
                            "category": "security",
                            "severity": "high",
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    manifest = repository / "manifest.json"
    manifest.write_text(
        dumps(
            {
                "schema_version": 1,
                "name": "snapshot-mismatch",
                "corpus": "corpus.json",
                "labeling_rules": "docs/labels.md",
                "source_snapshot": {
                    "repository": "example/repository",
                    "commit": source_commit,
                },
                "files": [
                    {
                        "path": "src/example.py",
                        "role": "positive",
                        "git_blob_sha1": git_blob_sha1(source.read_bytes()),
                    }
                ],
                "labels": [
                    {
                        "id": "SEC-1",
                        "path": "src/example.py",
                        "start_line": 1,
                        "end_line": 1,
                        "category": "security",
                        "severity": "high",
                        "control_id": "SEC-EXAMPLE-001",
                        "evidence_test": "tests/test_example.py::test_expected_issue",
                        "rationale": "Regression-only provenance test.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Snapshot blob mismatch"):
        validate_benchmark_corpus_provenance(corpus, manifest, repository)
