"""Comparative, gate-neutral evaluation for advisory review experiments."""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps, loads
from pathlib import Path, PurePosixPath
from statistics import mean
from typing import Any, Mapping, Sequence

from before_deploy.review_benchmark import ReviewBenchmarkResult, evaluate_advisory_output
from before_deploy.models import to_primitive

COMPARATIVE_BENCHMARK_SCHEMA = "before-deploy-comparative-benchmark-v1"
COMPARATIVE_AUTHORITY = "BENCHMARK_DIAGNOSTIC"
COMPARATIVE_GATE_EFFECT = "NONE"
DEPENDENCY_INITIAL = "initial_context_only"
DEPENDENCY_EXPANDED = "expanded_context_used"
_ALLOWED_DEPENDENCIES = {DEPENDENCY_INITIAL, DEPENDENCY_EXPANDED}
_ALLOWED_ROLES = {"STATIC", "EXPLORATORY"}


@dataclass(frozen=True)
class FindingEvidenceAttribution:
    fingerprint: str
    evidence_dependency: str
    supported_claim: bool
    citation_correct: bool


@dataclass(frozen=True)
class ComparativeRunSpec:
    run_id: str
    variant: str
    variant_role: str
    repetition: int
    advisory_file: str
    provider: str
    model: str
    context_bytes: int
    tool_calls: int
    latency_ms: int
    cost_microusd: int
    input_tokens: int
    output_tokens: int
    tool_names: tuple[str, ...]
    finding_evidence: tuple[FindingEvidenceAttribution, ...]


@dataclass(frozen=True)
class ComparativeRunResult:
    run_id: str
    variant: str
    variant_role: str
    repetition: int
    provider: str
    model: str
    benchmark: ReviewBenchmarkResult
    context_bytes: int
    tool_calls: int
    latency_ms: int
    cost_microusd: int
    input_tokens: int
    output_tokens: int
    tool_names: tuple[str, ...]
    supported_claims: int
    unsupported_claims: int
    citation_correct_claims: int
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    prediction_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class VariantAggregate:
    variant: str
    variant_role: str
    run_count: int
    mean_true_positives: float
    mean_false_positives: float
    mean_false_negatives: float
    mean_precision: float
    mean_recall: float
    mean_f1: float
    supported_claim_rate: float
    citation_correct_rate: float
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    mean_context_bytes: float
    mean_tool_calls: float
    mean_latency_ms: float
    mean_cost_microusd: float
    mean_input_tokens: float
    mean_output_tokens: float
    prediction_stability: float


@dataclass(frozen=True)
class ComparativeBenchmarkResult:
    name: str
    corpus_path: str
    runs: tuple[ComparativeRunResult, ...]
    variants: tuple[VariantAggregate, ...]
    schema_version: str = COMPARATIVE_BENCHMARK_SCHEMA
    authority: str = COMPARATIVE_AUTHORITY
    gate_effect: str = COMPARATIVE_GATE_EFFECT


def evaluate_comparative_manifest(
    corpus_path: Path,
    manifest_path: Path,
) -> ComparativeBenchmarkResult:
    """Evaluate repeated advisory variants with complete evidence-dependency attribution."""
    specs, name = load_comparative_manifest(manifest_path)
    run_results = tuple(
        _evaluate_run(corpus_path, manifest_path.parent, spec) for spec in specs
    )
    variants = tuple(
        _aggregate_variant(variant, tuple(item for item in run_results if item.variant == variant))
        for variant in sorted({item.variant for item in run_results})
    )
    return ComparativeBenchmarkResult(
        name=name,
        corpus_path=corpus_path.as_posix(),
        runs=run_results,
        variants=variants,
    )


def load_comparative_manifest(path: Path) -> tuple[tuple[ComparativeRunSpec, ...], str]:
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except ValueError as error:
        raise ValueError("Comparative benchmark manifest is not valid JSON") from error
    if not isinstance(payload, Mapping) or payload.get("schema_version") != COMPARATIVE_BENCHMARK_SCHEMA:
        raise ValueError("Unsupported comparative benchmark manifest schema")
    benchmark = payload.get("benchmark")
    if not isinstance(benchmark, Mapping):
        raise ValueError("Comparative benchmark manifest has no benchmark object")
    name = _required_text(benchmark, "name")
    raw_runs = benchmark.get("runs")
    if not isinstance(raw_runs, list) or not raw_runs:
        raise ValueError("Comparative benchmark requires at least one run")

    specs: list[ComparativeRunSpec] = []
    seen_run_ids: set[str] = set()
    seen_variant_repetitions: set[tuple[str, int]] = set()
    roles_by_variant: dict[str, str] = {}
    for index, raw in enumerate(raw_runs):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Comparative benchmark run {index + 1} must be an object")
        run_id = _required_text(raw, "run_id")
        variant = _required_text(raw, "variant")
        role = _required_text(raw, "variant_role").upper()
        if role not in _ALLOWED_ROLES:
            raise ValueError("variant_role must be STATIC or EXPLORATORY")
        repetition = _nonnegative_int(raw.get("repetition"), "repetition", positive=True)
        if run_id in seen_run_ids:
            raise ValueError(f"Duplicate comparative benchmark run_id: {run_id}")
        key = (variant, repetition)
        if key in seen_variant_repetitions:
            raise ValueError(f"Duplicate repetition {repetition} for variant {variant!r}")
        previous_role = roles_by_variant.setdefault(variant, role)
        if previous_role != role:
            raise ValueError(f"Variant {variant!r} mixes STATIC and EXPLORATORY roles")
        seen_run_ids.add(run_id)
        seen_variant_repetitions.add(key)

        tool_names = _text_tuple(raw.get("tool_names", []), "tool_names")
        if role == "STATIC" and (tool_names or _nonnegative_int(raw.get("tool_calls"), "tool_calls")):
            raise ValueError("STATIC benchmark runs cannot declare tool usage")
        finding_evidence = _finding_evidence(raw.get("finding_evidence", []))
        specs.append(
            ComparativeRunSpec(
                run_id=run_id,
                variant=variant,
                variant_role=role,
                repetition=repetition,
                advisory_file=_safe_relative_path(_required_text(raw, "advisory_file")),
                provider=_required_text(raw, "provider"),
                model=_required_text(raw, "model"),
                context_bytes=_nonnegative_int(raw.get("context_bytes"), "context_bytes"),
                tool_calls=_nonnegative_int(raw.get("tool_calls"), "tool_calls"),
                latency_ms=_nonnegative_int(raw.get("latency_ms"), "latency_ms"),
                cost_microusd=_nonnegative_int(raw.get("cost_microusd"), "cost_microusd"),
                input_tokens=_nonnegative_int(raw.get("input_tokens"), "input_tokens"),
                output_tokens=_nonnegative_int(raw.get("output_tokens"), "output_tokens"),
                tool_names=tool_names,
                finding_evidence=finding_evidence,
            )
        )
    return tuple(specs), name


def render_comparative_json(result: ComparativeBenchmarkResult) -> str:
    return dumps(
        {"schema_version": COMPARATIVE_BENCHMARK_SCHEMA, "comparative_benchmark": to_primitive(result)},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_comparative_markdown(result: ComparativeBenchmarkResult) -> str:
    lines = [
        "# Before Deploy Comparative Review Benchmark",
        "",
        f"- Experiment: `{result.name}`",
        f"- Authority: `{result.authority}`",
        f"- Gate effect: `{result.gate_effect}`",
        "",
        "| Variant | Role | Runs | TP | FP | FN | Precision | Recall | F1 | Supported | Citation correct | Explore TP | Explore FP | Stability | Mean tools | Mean context B | Mean latency ms | Mean cost µUSD |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in result.variants:
        lines.append(
            f"| {item.variant} | {item.variant_role} | {item.run_count} | "
            f"{item.mean_true_positives:.2f} | {item.mean_false_positives:.2f} | {item.mean_false_negatives:.2f} | "
            f"{item.mean_precision:.4f} | {item.mean_recall:.4f} | {item.mean_f1:.4f} | "
            f"{item.supported_claim_rate:.4f} | {item.citation_correct_rate:.4f} | "
            f"{item.exploration_attributable_tp} | {item.exploration_attributable_fp} | "
            f"{item.prediction_stability:.4f} | {item.mean_tool_calls:.2f} | {item.mean_context_bytes:.2f} | "
            f"{item.mean_latency_ms:.2f} | {item.mean_cost_microusd:.2f} |"
        )
    lines.extend(
        [
            "",
            "> Comparative results are experiment diagnostics only. They never change PolicyDecision or release disposition.",
        ]
    )
    return "\n".join(lines) + "\n"


def _evaluate_run(corpus_path: Path, manifest_dir: Path, spec: ComparativeRunSpec) -> ComparativeRunResult:
    advisory_path = _resolve_bounded(manifest_dir, spec.advisory_file)
    benchmark = evaluate_advisory_output(corpus_path, advisory_path)
    predicted = {
        match.advisory_fingerprint for match in benchmark.matches
    } | {
        item.advisory_fingerprint for item in benchmark.unmatched_predictions
    }
    attribution = {item.fingerprint: item for item in spec.finding_evidence}
    if predicted != set(attribution):
        missing = sorted(predicted - set(attribution))
        extra = sorted(set(attribution) - predicted)
        raise ValueError(
            f"Run {spec.run_id!r} finding attribution mismatch: missing={missing}, extra={extra}"
        )
    if spec.variant_role == "STATIC" and any(
        item.evidence_dependency != DEPENDENCY_INITIAL for item in attribution.values()
    ):
        raise ValueError("STATIC run cannot attribute findings to expanded context")

    matched = {item.advisory_fingerprint for item in benchmark.matches}
    false_positive = {item.advisory_fingerprint for item in benchmark.unmatched_predictions}
    supported = sum(item.supported_claim for item in attribution.values())
    citation_correct = sum(item.citation_correct for item in attribution.values())
    exploration_tp = sum(
        fingerprint in matched and item.evidence_dependency == DEPENDENCY_EXPANDED
        for fingerprint, item in attribution.items()
    )
    exploration_fp = sum(
        fingerprint in false_positive and item.evidence_dependency == DEPENDENCY_EXPANDED
        for fingerprint, item in attribution.items()
    )
    return ComparativeRunResult(
        run_id=spec.run_id,
        variant=spec.variant,
        variant_role=spec.variant_role,
        repetition=spec.repetition,
        provider=spec.provider,
        model=spec.model,
        benchmark=benchmark,
        context_bytes=spec.context_bytes,
        tool_calls=spec.tool_calls,
        latency_ms=spec.latency_ms,
        cost_microusd=spec.cost_microusd,
        input_tokens=spec.input_tokens,
        output_tokens=spec.output_tokens,
        tool_names=spec.tool_names,
        supported_claims=supported,
        unsupported_claims=len(attribution) - supported,
        citation_correct_claims=citation_correct,
        exploration_attributable_tp=exploration_tp,
        exploration_attributable_fp=exploration_fp,
        prediction_fingerprints=tuple(sorted(predicted)),
    )


def _aggregate_variant(variant: str, runs: tuple[ComparativeRunResult, ...]) -> VariantAggregate:
    roles = {item.variant_role for item in runs}
    if len(roles) != 1:
        raise ValueError(f"Variant {variant!r} has inconsistent roles")
    claim_count = sum(item.supported_claims + item.unsupported_claims for item in runs)
    correct_count = sum(item.citation_correct_claims for item in runs)
    return VariantAggregate(
        variant=variant,
        variant_role=next(iter(roles)),
        run_count=len(runs),
        mean_true_positives=mean(item.benchmark.true_positives for item in runs),
        mean_false_positives=mean(item.benchmark.false_positives for item in runs),
        mean_false_negatives=mean(item.benchmark.false_negatives for item in runs),
        mean_precision=mean(item.benchmark.precision for item in runs),
        mean_recall=mean(item.benchmark.recall for item in runs),
        mean_f1=mean(item.benchmark.f1 for item in runs),
        supported_claim_rate=(sum(item.supported_claims for item in runs) / claim_count if claim_count else 1.0),
        citation_correct_rate=(correct_count / claim_count if claim_count else 1.0),
        exploration_attributable_tp=sum(item.exploration_attributable_tp for item in runs),
        exploration_attributable_fp=sum(item.exploration_attributable_fp for item in runs),
        mean_context_bytes=mean(item.context_bytes for item in runs),
        mean_tool_calls=mean(item.tool_calls for item in runs),
        mean_latency_ms=mean(item.latency_ms for item in runs),
        mean_cost_microusd=mean(item.cost_microusd for item in runs),
        mean_input_tokens=mean(item.input_tokens for item in runs),
        mean_output_tokens=mean(item.output_tokens for item in runs),
        prediction_stability=_prediction_stability(runs),
    )


def _prediction_stability(runs: Sequence[ComparativeRunResult]) -> float:
    if len(runs) < 2:
        return 1.0
    sets = [set(item.prediction_fingerprints) for item in runs]
    scores: list[float] = []
    for left_index, left in enumerate(sets):
        for right in sets[left_index + 1 :]:
            union = left | right
            scores.append(len(left & right) / len(union) if union else 1.0)
    return mean(scores) if scores else 1.0


def _finding_evidence(value: Any) -> tuple[FindingEvidenceAttribution, ...]:
    if not isinstance(value, list):
        raise ValueError("finding_evidence must be an array")
    items: list[FindingEvidenceAttribution] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise ValueError("finding_evidence entries must be objects")
        fingerprint = _required_text(raw, "fingerprint")
        if fingerprint in seen:
            raise ValueError(f"Duplicate finding evidence attribution: {fingerprint}")
        dependency = _required_text(raw, "evidence_dependency")
        if dependency not in _ALLOWED_DEPENDENCIES:
            raise ValueError("Unsupported evidence_dependency")
        supported = raw.get("supported_claim")
        citation_correct = raw.get("citation_correct")
        if not isinstance(supported, bool) or not isinstance(citation_correct, bool):
            raise ValueError("supported_claim and citation_correct must be booleans")
        seen.add(fingerprint)
        items.append(
            FindingEvidenceAttribution(
                fingerprint=fingerprint,
                evidence_dependency=dependency,
                supported_claim=supported,
                citation_correct=citation_correct,
            )
        )
    return tuple(sorted(items, key=lambda item: item.fingerprint))


def _resolve_bounded(root: Path, relative: str) -> Path:
    base = root.resolve()
    path = (base / Path(*PurePosixPath(relative).parts)).resolve()
    if path != base and base not in path.parents:
        raise ValueError("Comparative benchmark advisory path escapes the manifest directory")
    return path


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Comparative benchmark file path must be repository-relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("Comparative benchmark file path must not be an absolute drive path")
    return candidate.as_posix()


def _text_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return tuple(value)


def _required_text(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Comparative benchmark field {key!r} must be non-empty text")
    return value.strip()


def _nonnegative_int(value: Any, key: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"Comparative benchmark field {key!r} must be a {qualifier} integer")
    return value
