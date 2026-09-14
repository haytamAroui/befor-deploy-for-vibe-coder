from __future__ import annotations

from json import loads

import pytest

from before_deploy.advisory import AdvisoryFinding
from before_deploy.models import Location
from before_deploy.review_benchmark import (
    BenchmarkCorpus,
    ExpectedDefect,
    evaluate_advisory_output,
    evaluate_findings,
    load_benchmark_corpus,
    render_benchmark_json,
    render_benchmark_markdown,
)


def _finding(
    fingerprint: str,
    *,
    path: str | None,
    start: int | None,
    end: int | None = None,
    category: str = "bug",
    severity: str = "high",
) -> AdvisoryFinding:
    location = None
    if path is not None:
        location = Location(path=path, start_line=start, end_line=end or start)
    return AdvisoryFinding(
        finding_id=f"ADV-{fingerprint}",
        source="test-reviewer",
        title=f"Finding {fingerprint}",
        message="benchmark test",
        category=category,
        severity=severity,
        confidence=None,
        fingerprint=fingerprint,
        location=location,
    )


def _corpus(*defects: ExpectedDefect) -> BenchmarkCorpus:
    return BenchmarkCorpus(name="unit-corpus", defects=tuple(defects))


def test_exact_path_category_and_line_overlap_match():
    corpus = _corpus(
        ExpectedDefect(
            defect_id="BUG-1",
            path="src/app.py",
            start_line=10,
            end_line=12,
            category="bug",
        )
    )
    finding = _finding("pred-1", path="src/app.py", start=12, end=14)

    result = evaluate_findings(
        corpus,
        (finding,),
        source="test-reviewer",
        source_format="test-json",
    )

    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0
    assert result.matches[0].defect_id == "BUG-1"
    assert result.gate_effect == "NONE"


def test_wrong_category_is_false_positive_and_false_negative():
    corpus = _corpus(
        ExpectedDefect(
            defect_id="SEC-1",
            path="src/app.py",
            start_line=5,
            end_line=5,
            category="security",
        )
    )
    finding = _finding("pred-1", path="src/app.py", start=5, category="bug")

    result = evaluate_findings(corpus, (finding,), source="reviewer", source_format="json")

    assert result.true_positives == 0
    assert result.false_positives == 1
    assert result.false_negatives == 1
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def test_prediction_without_location_cannot_match_line_level_ground_truth():
    corpus = _corpus(
        ExpectedDefect(
            defect_id="BUG-1",
            path="src/app.py",
            start_line=1,
            end_line=1,
            category="bug",
        )
    )
    finding = _finding("pred-no-location", path=None, start=None)

    result = evaluate_findings(corpus, (finding,), source="reviewer", source_format="json")

    assert result.false_positives == 1
    assert result.false_negatives == 1
    assert result.unmatched_predictions[0].path is None


def test_duplicate_predictions_do_not_inflate_recall():
    corpus = _corpus(
        ExpectedDefect(
            defect_id="BUG-1",
            path="src/app.py",
            start_line=10,
            end_line=10,
            category="bug",
        )
    )
    findings = (
        _finding("a", path="src/app.py", start=10),
        _finding("b", path="src/app.py", start=10),
    )

    result = evaluate_findings(corpus, findings, source="reviewer", source_format="json")

    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.false_negatives == 0
    assert result.recall == 1.0
    assert result.precision == 0.5


def test_maximum_matching_handles_overlapping_ground_truth_without_greedy_undercount():
    corpus = _corpus(
        ExpectedDefect(
            defect_id="BUG-A",
            path="src/app.py",
            start_line=10,
            end_line=20,
            category="bug",
        ),
        ExpectedDefect(
            defect_id="BUG-B",
            path="src/app.py",
            start_line=20,
            end_line=30,
            category="bug",
        ),
    )
    findings = (
        _finding("a-flexible", path="src/app.py", start=20),
        _finding("b-only-a", path="src/app.py", start=11),
    )

    result = evaluate_findings(corpus, findings, source="reviewer", source_format="json")

    assert result.true_positives == 2
    assert result.false_positives == 0
    assert result.false_negatives == 0


def test_per_category_metrics_are_independent():
    corpus = _corpus(
        ExpectedDefect(
            defect_id="BUG-1",
            path="src/app.py",
            start_line=1,
            end_line=1,
            category="bug",
        ),
        ExpectedDefect(
            defect_id="SEC-1",
            path="src/auth.py",
            start_line=2,
            end_line=2,
            category="security",
        ),
    )
    findings = (
        _finding("bug-hit", path="src/app.py", start=1, category="bug"),
        _finding("security-fp", path="src/other.py", start=99, category="security"),
    )

    result = evaluate_findings(corpus, findings, source="reviewer", source_format="json")
    metrics = {item.category: item for item in result.category_metrics}

    assert metrics["bug"].true_positives == 1
    assert metrics["bug"].f1 == 1.0
    assert metrics["security"].true_positives == 0
    assert metrics["security"].false_positives == 1
    assert metrics["security"].false_negatives == 1
    assert metrics["security"].f1 == 0.0


def test_empty_corpus_and_empty_predictions_is_perfect_no_error_case():
    result = evaluate_findings(
        BenchmarkCorpus(name="empty", defects=()),
        (),
        source="reviewer",
        source_format="json",
    )

    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0


def test_load_corpus_rejects_duplicate_ids_and_unsafe_paths(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        """{
          "schema_version": 1,
          "benchmark": {
            "name": "bad",
            "defects": [
              {"id":"D1","path":"src/a.py","start_line":1,"category":"bug"},
              {"id":"D1","path":"src/b.py","start_line":1,"category":"bug"}
            ]
          }
        }""",
        encoding="utf-8",
    )
    traversal = tmp_path / "traversal.json"
    traversal.write_text(
        """{
          "schema_version": 1,
          "benchmark": {
            "name": "bad",
            "defects": [
              {"id":"D1","path":"../outside.py","start_line":1,"category":"bug"}
            ]
          }
        }""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate"):
        load_benchmark_corpus(duplicate)
    with pytest.raises(ValueError, match="repository-relative"):
        load_benchmark_corpus(traversal)


def test_evaluate_accepts_ocr_json_and_renders_machine_and_human_reports(tmp_path):
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(
        """{
          "schema_version": 1,
          "benchmark": {
            "name": "sample",
            "defects": [
              {"id":"BUG-1","path":"src/app.py","start_line":7,"end_line":8,"category":"bug"}
            ]
          }
        }""",
        encoding="utf-8",
    )
    advisory_path = tmp_path / "ocr.json"
    advisory_path.write_text(
        """{
          "comments": [
            {"path":"src/app.py","start_line":7,"end_line":7,"category":"bug","severity":"high","content":"Possible bug"}
          ]
        }""",
        encoding="utf-8",
    )

    result = evaluate_advisory_output(corpus_path, advisory_path)
    rendered_json = render_benchmark_json(result)
    rendered_markdown = render_benchmark_markdown(result)
    payload = loads(rendered_json)

    assert result.source == "open-code-review"
    assert payload["review_benchmark"]["f1"] == 1.0
    assert payload["review_benchmark"]["gate_effect"] == "NONE"
    assert "Precision: **1.0000**" in rendered_markdown
    assert "diagnostics only" in rendered_markdown
