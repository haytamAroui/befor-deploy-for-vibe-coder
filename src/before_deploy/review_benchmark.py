"""Deterministic evaluation of advisory review output against labeled defects."""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps, loads
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from before_deploy.advisory import AdvisoryFinding, load_advisory_file
from before_deploy.models import Location, to_primitive

BENCHMARK_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ExpectedDefect:
    """One human-labeled benchmark defect with a strict source anchor."""

    defect_id: str
    path: str
    start_line: int
    end_line: int
    category: str
    severity: str | None = None


@dataclass(frozen=True)
class BenchmarkCorpus:
    """Versioned labeled defect corpus for deterministic review evaluation."""

    name: str
    defects: tuple[ExpectedDefect, ...]


@dataclass(frozen=True)
class BenchmarkMatch:
    """One one-to-one prediction/ground-truth match."""

    defect_id: str
    advisory_fingerprint: str
    path: str
    category: str
    expected_start_line: int
    expected_end_line: int
    predicted_start_line: int
    predicted_end_line: int


@dataclass(frozen=True)
class BenchmarkMiss:
    """A labeled defect not matched by any advisory finding."""

    defect_id: str
    path: str
    category: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class BenchmarkFalsePositive:
    """An advisory finding that did not match any labeled defect."""

    advisory_fingerprint: str
    path: str | None
    category: str
    start_line: int | None
    end_line: int | None
    severity: str


@dataclass(frozen=True)
class BenchmarkCategoryMetrics:
    """Per-category deterministic classification metrics."""

    category: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class ReviewBenchmarkResult:
    """Complete deterministic benchmark result for one advisory output."""

    corpus_name: str
    source: str
    source_format: str
    expected_count: int
    prediction_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    matches: tuple[BenchmarkMatch, ...]
    misses: tuple[BenchmarkMiss, ...]
    unmatched_predictions: tuple[BenchmarkFalsePositive, ...]
    category_metrics: tuple[BenchmarkCategoryMetrics, ...]
    matching_contract: str = "exact_path+exact_category+line_overlap+one_to_one"
    authority: str = "BENCHMARK_DIAGNOSTIC"
    gate_effect: str = "NONE"


def load_benchmark_corpus(path: Path) -> BenchmarkCorpus:
    """Load a strict benchmark corpus without executing repository content."""
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except ValueError as error:
        raise ValueError("Benchmark corpus is not valid JSON") from error
    if not isinstance(payload, Mapping) or payload.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
        raise ValueError("Unsupported benchmark corpus schema")
    benchmark = payload.get("benchmark")
    if not isinstance(benchmark, Mapping):
        raise ValueError("Benchmark corpus has no benchmark object")
    name = _required_text(benchmark, "name")
    raw_defects = benchmark.get("defects")
    if not isinstance(raw_defects, list):
        raise ValueError("Benchmark defects must be an array")

    defects: list[ExpectedDefect] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_defects):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Benchmark defect {index + 1} must be an object")
        defect_id = _required_text(raw, "id")
        if defect_id in seen_ids:
            raise ValueError(f"Duplicate benchmark defect id: {defect_id}")
        seen_ids.add(defect_id)
        path_text = _safe_relative_path(_required_text(raw, "path"))
        start_line = _positive_int(raw.get("start_line"), "start_line")
        end_line = _positive_int(raw.get("end_line", start_line), "end_line")
        if end_line < start_line:
            raise ValueError(f"Benchmark defect {defect_id} has end_line before start_line")
        category = _required_text(raw, "category").lower()
        severity = _optional_text(raw.get("severity"))
        defects.append(
            ExpectedDefect(
                defect_id=defect_id,
                path=path_text,
                start_line=start_line,
                end_line=end_line,
                category=category,
                severity=severity.lower() if severity else None,
            )
        )
    return BenchmarkCorpus(name=name, defects=tuple(defects))


def evaluate_advisory_output(corpus_path: Path, advisory_path: Path) -> ReviewBenchmarkResult:
    """Evaluate a normalized/OCR advisory result against a labeled corpus."""
    corpus = load_benchmark_corpus(corpus_path)
    advisory = load_advisory_file(advisory_path)
    return evaluate_findings(corpus, advisory.findings, source=advisory.source, source_format=advisory.source_format)


def evaluate_findings(
    corpus: BenchmarkCorpus,
    findings: tuple[AdvisoryFinding, ...],
    *,
    source: str,
    source_format: str,
) -> ReviewBenchmarkResult:
    """Score findings using deterministic maximum one-to-one matching."""
    defects = tuple(sorted(corpus.defects, key=lambda item: item.defect_id))
    predictions = tuple(sorted(findings, key=lambda item: item.fingerprint))
    edges = _candidate_edges(defects, predictions)
    defect_to_prediction = _maximum_matching(edges, len(defects), len(predictions))
    matched_prediction_indices = set(defect_to_prediction.values())

    matches: list[BenchmarkMatch] = []
    misses: list[BenchmarkMiss] = []
    for defect_index, defect in enumerate(defects):
        prediction_index = defect_to_prediction.get(defect_index)
        if prediction_index is None:
            misses.append(
                BenchmarkMiss(
                    defect_id=defect.defect_id,
                    path=defect.path,
                    category=defect.category,
                    start_line=defect.start_line,
                    end_line=defect.end_line,
                )
            )
            continue
        prediction = predictions[prediction_index]
        location = prediction.location
        assert location is not None and location.start_line is not None
        matches.append(
            BenchmarkMatch(
                defect_id=defect.defect_id,
                advisory_fingerprint=prediction.fingerprint,
                path=defect.path,
                category=defect.category,
                expected_start_line=defect.start_line,
                expected_end_line=defect.end_line,
                predicted_start_line=location.start_line,
                predicted_end_line=location.end_line or location.start_line,
            )
        )

    false_positives = tuple(
        _false_positive(prediction)
        for index, prediction in enumerate(predictions)
        if index not in matched_prediction_indices
    )
    true_positive_count = len(matches)
    false_positive_count = len(false_positives)
    false_negative_count = len(misses)
    precision, recall, f1 = _metrics(
        true_positive_count,
        false_positive_count,
        false_negative_count,
    )
    category_metrics = _category_metrics(defects, predictions, defect_to_prediction)
    return ReviewBenchmarkResult(
        corpus_name=corpus.name,
        source=source,
        source_format=source_format,
        expected_count=len(defects),
        prediction_count=len(predictions),
        true_positives=true_positive_count,
        false_positives=false_positive_count,
        false_negatives=false_negative_count,
        precision=precision,
        recall=recall,
        f1=f1,
        matches=tuple(matches),
        misses=tuple(misses),
        unmatched_predictions=false_positives,
        category_metrics=category_metrics,
    )


def render_benchmark_json(result: ReviewBenchmarkResult) -> str:
    return dumps(
        {"schema_version": 1, "review_benchmark": to_primitive(result)},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_benchmark_markdown(result: ReviewBenchmarkResult) -> str:
    lines = [
        "# Before Deploy Review Benchmark",
        "",
        f"- Corpus: `{result.corpus_name}`",
        f"- Source: `{result.source}` / `{result.source_format}`",
        f"- Matching: `{result.matching_contract}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "## Overall",
        "",
        f"- Expected defects: **{result.expected_count}**",
        f"- Predictions: **{result.prediction_count}**",
        f"- True positives: **{result.true_positives}**",
        f"- False positives: **{result.false_positives}**",
        f"- False negatives: **{result.false_negatives}**",
        f"- Precision: **{result.precision:.4f}**",
        f"- Recall: **{result.recall:.4f}**",
        f"- F1: **{result.f1:.4f}**",
        "",
        "## Per category",
        "",
        "| Category | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in result.category_metrics:
        lines.append(
            f"| {item.category} | {item.true_positives} | {item.false_positives} | "
            f"{item.false_negatives} | {item.precision:.4f} | {item.recall:.4f} | {item.f1:.4f} |"
        )
    lines.extend(["", "## Missed labeled defects", ""])
    if result.misses:
        for miss in result.misses:
            lines.append(
                f"- `{miss.defect_id}` `{miss.category}` `{miss.path}:{miss.start_line}-{miss.end_line}`"
            )
    else:
        lines.append("None.")
    lines.extend(["", "## Unmatched predictions", ""])
    if result.unmatched_predictions:
        for finding in result.unmatched_predictions:
            location = finding.path or "<no-location>"
            if finding.start_line is not None:
                location += f":{finding.start_line}-{finding.end_line or finding.start_line}"
            lines.append(
                f"- `{finding.category}` `{finding.severity}` `{location}` "
                f"fingerprint `{finding.advisory_fingerprint}`"
            )
    else:
        lines.append("None.")
    lines.extend(
        [
            "",
            "> Benchmark results are diagnostics only. They do not change release policy or gate status.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _candidate_edges(
    defects: tuple[ExpectedDefect, ...],
    predictions: tuple[AdvisoryFinding, ...],
) -> tuple[tuple[int, ...], ...]:
    rows = []
    for defect in defects:
        candidates = [
            prediction_index
            for prediction_index, prediction in enumerate(predictions)
            if _matches(defect, prediction)
        ]
        rows.append(tuple(candidates))
    return tuple(rows)


def _matches(defect: ExpectedDefect, prediction: AdvisoryFinding) -> bool:
    location = prediction.location
    if location is None or location.start_line is None:
        return False
    if location.path != defect.path or prediction.category != defect.category:
        return False
    prediction_end = location.end_line or location.start_line
    return defect.start_line <= prediction_end and location.start_line <= defect.end_line


def _maximum_matching(
    edges: tuple[tuple[int, ...], ...],
    defect_count: int,
    prediction_count: int,
) -> dict[int, int]:
    """Return deterministic maximum-cardinality bipartite matching."""
    prediction_to_defect: dict[int, int] = {}

    def augment(defect_index: int, seen: set[int]) -> bool:
        for prediction_index in edges[defect_index]:
            if prediction_index in seen:
                continue
            seen.add(prediction_index)
            owner = prediction_to_defect.get(prediction_index)
            if owner is None or augment(owner, seen):
                prediction_to_defect[prediction_index] = defect_index
                return True
        return False

    for defect_index in range(defect_count):
        augment(defect_index, set())
    return {defect: prediction for prediction, defect in prediction_to_defect.items()}


def _category_metrics(
    defects: tuple[ExpectedDefect, ...],
    predictions: tuple[AdvisoryFinding, ...],
    matching: dict[int, int],
) -> tuple[BenchmarkCategoryMetrics, ...]:
    categories = sorted({item.category for item in defects} | {item.category for item in predictions})
    matched_predictions = set(matching.values())
    rows = []
    for category in categories:
        tp = sum(defects[index].category == category for index in matching)
        fn = sum(item.category == category for item in defects) - tp
        fp = sum(
            prediction.category == category and index not in matched_predictions
            for index, prediction in enumerate(predictions)
        )
        precision, recall, f1 = _metrics(tp, fp, fn)
        rows.append(
            BenchmarkCategoryMetrics(
                category=category,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=precision,
                recall=recall,
                f1=f1,
            )
        )
    return tuple(rows)


def _false_positive(prediction: AdvisoryFinding) -> BenchmarkFalsePositive:
    location = prediction.location
    return BenchmarkFalsePositive(
        advisory_fingerprint=prediction.fingerprint,
        path=location.path if location else None,
        category=prediction.category,
        start_line=location.start_line if location else None,
        end_line=location.end_line if location else None,
        severity=prediction.severity,
    )


def _metrics(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Benchmark defect path must be repository-relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("Benchmark defect path must not be an absolute drive path")
    return candidate.as_posix()


def _required_text(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Benchmark field {key!r} must be non-empty text")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Benchmark optional text value must be non-empty when present")
    return value.strip()


def _positive_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Benchmark field {key!r} must be a positive integer")
    return value
