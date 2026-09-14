from __future__ import annotations

from json import dumps, loads
from pathlib import Path

import pytest

from before_deploy.review_benchmark import evaluate_advisory_output
from before_deploy.review_benchmark_corpus import validate_benchmark_corpus_provenance

ROOT = Path(__file__).parents[2]
CORPUS = ROOT / "fixtures" / "review-benchmark-v1" / "corpus.json"
MANIFEST = ROOT / "fixtures" / "review-benchmark-v1" / "manifest.json"
ORACLE = ROOT / "fixtures" / "review-benchmark-v1" / "oracle-advisory.json"


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
