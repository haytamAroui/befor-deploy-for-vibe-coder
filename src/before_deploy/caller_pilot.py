"""Engineering STOP/GO evaluation for the minimal `find_callers` pilot."""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps, loads
from pathlib import Path, PurePosixPath
from statistics import mean
from typing import Any, Mapping

from before_deploy.caller_experiment import InitialEvidence
from before_deploy.comparative_benchmark import (
    ComparativeBenchmarkResult,
    ComparativeRunResult,
    evaluate_comparative_manifest,
)
from before_deploy.models import to_primitive

CALLER_PILOT_CASE_SCHEMA = "before-deploy-caller-pilot-cases-v1"
CALLER_PILOT_RESULT_SCHEMA = "before-deploy-caller-pilot-result-v1"
STATIC_SUFFICIENT = "STATIC-SUFFICIENT"
EXPLORATION_REQUIRED = "EXPLORATION-REQUIRED"
FALSE_POSITIVE_TRAP = "FALSE-POSITIVE-TRAP"
_ALLOWED_CLASSES = {STATIC_SUFFICIENT, EXPLORATION_REQUIRED, FALSE_POSITIVE_TRAP}


@dataclass(frozen=True)
class PilotRegion:
    path: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class PilotCase:
    case_id: str
    case_class: str
    initial_path: str
    initial_start_line: int
    initial_end_line: int
    symbol: str
    regions: tuple[PilotRegion, ...]
    defect_id: str | None


@dataclass(frozen=True)
class PilotDefinition:
    name: str
    repository: str
    cases: tuple[PilotCase, ...]


@dataclass(frozen=True)
class PilotVariantMetrics:
    variant: str
    variant_role: str
    run_count: int
    static_sufficient_recall: float
    exploration_required_recall: float
    false_positive_trap_rate: float
    supported_claim_rate: float
    citation_correct_rate: float
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    mean_context_bytes: float
    mean_tool_calls: float
    mean_latency_ms: float
    mean_cost_microusd: float
    prediction_stability: float
    exact_prediction_stability: float


@dataclass(frozen=True)
class CallerPilotAssessment:
    pilot_name: str
    decision: str
    reason_codes: tuple[str, ...]
    static_variant: PilotVariantMetrics
    exploratory_variant: PilotVariantMetrics
    exploration_required_recall_lift: float
    false_positive_trap_rate_delta: float
    static_sufficient_recall_delta: float
    scope: str = "ENGINEERING_PILOT_NOT_STATISTICAL_CLAIM"
    authority: str = "BENCHMARK_DIAGNOSTIC"
    gate_effect: str = "NONE"
    schema_version: str = CALLER_PILOT_RESULT_SCHEMA


def evaluate_caller_pilot(
    *,
    corpus_path: Path,
    comparative_manifest_path: Path,
    cases_path: Path,
) -> CallerPilotAssessment:
    definition = load_pilot_definition(cases_path)
    comparative = evaluate_comparative_manifest(corpus_path, comparative_manifest_path)
    metrics = tuple(_variant_metrics(definition, comparative, variant) for variant in comparative.variants)
    static = [item for item in metrics if item.variant_role == "STATIC"]
    exploratory = [item for item in metrics if item.variant_role == "EXPLORATORY"]
    if len(static) != 1 or len(exploratory) != 1:
        raise ValueError("Caller pilot requires exactly one STATIC and one EXPLORATORY variant")
    static_item = static[0]
    exploratory_item = exploratory[0]
    recall_lift = exploratory_item.exploration_required_recall - static_item.exploration_required_recall
    trap_delta = exploratory_item.false_positive_trap_rate - static_item.false_positive_trap_rate
    static_delta = exploratory_item.static_sufficient_recall - static_item.static_sufficient_recall

    reasons: list[str] = []
    if recall_lift <= 0:
        reasons.append("NO_EXPLORATION_REQUIRED_RECALL_LIFT")
    if exploratory_item.exploration_attributable_tp <= 0:
        reasons.append("NO_EXPLORATION_ATTRIBUTABLE_TRUE_POSITIVE")
    if exploratory_item.exploration_attributable_tp <= exploratory_item.exploration_attributable_fp:
        reasons.append("EXPLORATION_ATTRIBUTABLE_FP_NOT_LOWER_THAN_TP")
    if trap_delta > 0:
        reasons.append("FALSE_POSITIVE_TRAP_RATE_INCREASED")
    if static_delta < 0:
        reasons.append("STATIC_SUFFICIENT_RECALL_REGRESSED")
    if exploratory_item.supported_claim_rate < 1.0:
        reasons.append("UNSUPPORTED_EXPLORATORY_CLAIM")
    if exploratory_item.citation_correct_rate < 1.0:
        reasons.append("EXPLORATORY_CITATION_ERROR")
    decision = "GO" if not reasons else "STOP"
    return CallerPilotAssessment(
        pilot_name=definition.name,
        decision=decision,
        reason_codes=tuple(reasons),
        static_variant=static_item,
        exploratory_variant=exploratory_item,
        exploration_required_recall_lift=recall_lift,
        false_positive_trap_rate_delta=trap_delta,
        static_sufficient_recall_delta=static_delta,
    )


def load_pilot_definition(path: Path) -> PilotDefinition:
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except ValueError as error:
        raise ValueError("Caller pilot cases are not valid JSON") from error
    if not isinstance(payload, Mapping) or payload.get("schema_version") != CALLER_PILOT_CASE_SCHEMA:
        raise ValueError("Unsupported caller pilot case schema")
    pilot = payload.get("pilot")
    if not isinstance(pilot, Mapping):
        raise ValueError("Caller pilot definition has no pilot object")
    name = _required_text(pilot, "name")
    repository = _safe_path(_required_text(pilot, "repository"))
    raw_cases = pilot.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("Caller pilot must contain cases")
    cases: list[PilotCase] = []
    seen_ids: set[str] = set()
    seen_defects: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, Mapping):
            raise ValueError("Caller pilot case must be an object")
        case_id = _required_text(raw, "id")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate caller pilot case: {case_id}")
        seen_ids.add(case_id)
        case_class = _required_text(raw, "class").upper()
        if case_class not in _ALLOWED_CLASSES:
            raise ValueError(f"Unsupported caller pilot class: {case_class}")
        start = _positive_int(raw.get("initial_start_line"), "initial_start_line")
        end = _positive_int(raw.get("initial_end_line"), "initial_end_line")
        if end < start:
            raise ValueError("Caller pilot initial range is reversed")
        regions = _regions(raw.get("regions"))
        defect = raw.get("defect_id")
        if case_class == FALSE_POSITIVE_TRAP:
            if defect is not None:
                raise ValueError("FALSE-POSITIVE-TRAP cases cannot have defect_id")
            defect_id = None
        else:
            if not isinstance(defect, str) or not defect.strip():
                raise ValueError("Positive caller pilot cases require defect_id")
            defect_id = defect.strip()
            if defect_id in seen_defects:
                raise ValueError(f"Duplicate caller pilot defect_id: {defect_id}")
            seen_defects.add(defect_id)
        cases.append(
            PilotCase(
                case_id=case_id,
                case_class=case_class,
                initial_path=_safe_path(_required_text(raw, "initial_path")),
                initial_start_line=start,
                initial_end_line=end,
                symbol=_required_text(raw, "symbol"),
                regions=regions,
                defect_id=defect_id,
            )
        )
    present = {item.case_class for item in cases}
    if present != _ALLOWED_CLASSES:
        raise ValueError("Caller pilot must contain all three hypothesis classes")
    return PilotDefinition(name=name, repository=repository, cases=tuple(cases))


def prepare_initial_evidence(cases_path: Path, case_id: str) -> tuple[Path, PilotCase, InitialEvidence]:
    """Materialize exactly the declared initial range for one blinded pilot case."""
    definition = load_pilot_definition(cases_path)
    matches = [item for item in definition.cases if item.case_id == case_id]
    if len(matches) != 1:
        raise ValueError(f"Unknown caller pilot case: {case_id}")
    case = matches[0]
    repository = (cases_path.parent / definition.repository).resolve()
    source = (repository / Path(*PurePosixPath(case.initial_path).parts)).resolve()
    if repository not in source.parents:
        raise ValueError("Caller pilot initial path escapes repository")
    lines = source.read_text(encoding="utf-8").splitlines()
    if case.initial_end_line > len(lines):
        raise ValueError("Caller pilot initial range exceeds source file")
    content = "\n".join(lines[case.initial_start_line - 1 : case.initial_end_line]) + "\n"
    evidence = InitialEvidence.from_text(
        evidence_id=f"pilot-initial:{case.case_id}",
        path=case.initial_path,
        content=content,
    )
    return repository, case, evidence


def render_pilot_json(result: CallerPilotAssessment) -> str:
    return dumps(
        {"schema_version": CALLER_PILOT_RESULT_SCHEMA, "caller_pilot": to_primitive(result)},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_pilot_markdown(result: CallerPilotAssessment) -> str:
    lines = [
        "# Before Deploy `find_callers` Pilot",
        "",
        f"- Decision: **{result.decision}**",
        f"- Scope: `{result.scope}`",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        f"- Exploration-required recall lift: **{result.exploration_required_recall_lift:+.4f}**",
        f"- False-positive-trap rate delta: **{result.false_positive_trap_rate_delta:+.4f}**",
        f"- Static-sufficient recall delta: **{result.static_sufficient_recall_delta:+.4f}**",
        (
            "- Exploratory claim stability: "
            f"**{result.exploratory_variant.prediction_stability:.4f}** "
            "(exact fingerprint stability "
            f"{result.exploratory_variant.exact_prediction_stability:.4f})"
        ),
        "",
        "## Reasons",
        "",
    ]
    lines.extend(f"- `{reason}`" for reason in result.reason_codes)
    if not result.reason_codes:
        lines.append("- No stop condition triggered.")
    return "\n".join(lines) + "\n"


def _variant_metrics(
    definition: PilotDefinition,
    comparative: ComparativeBenchmarkResult,
    aggregate,
) -> PilotVariantMetrics:
    runs = tuple(item for item in comparative.runs if item.variant == aggregate.variant)
    static_cases = tuple(item for item in definition.cases if item.case_class == STATIC_SUFFICIENT)
    exploration_cases = tuple(item for item in definition.cases if item.case_class == EXPLORATION_REQUIRED)
    trap_cases = tuple(item for item in definition.cases if item.case_class == FALSE_POSITIVE_TRAP)
    return PilotVariantMetrics(
        variant=aggregate.variant,
        variant_role=aggregate.variant_role,
        run_count=len(runs),
        static_sufficient_recall=mean(_class_recall(run, static_cases) for run in runs),
        exploration_required_recall=mean(_class_recall(run, exploration_cases) for run in runs),
        false_positive_trap_rate=mean(_trap_rate(run, trap_cases) for run in runs),
        supported_claim_rate=aggregate.supported_claim_rate,
        citation_correct_rate=aggregate.citation_correct_rate,
        exploration_attributable_tp=aggregate.exploration_attributable_tp,
        exploration_attributable_fp=aggregate.exploration_attributable_fp,
        mean_context_bytes=aggregate.mean_context_bytes,
        mean_tool_calls=aggregate.mean_tool_calls,
        mean_latency_ms=aggregate.mean_latency_ms,
        mean_cost_microusd=aggregate.mean_cost_microusd,
        prediction_stability=aggregate.prediction_stability,
        exact_prediction_stability=aggregate.exact_prediction_stability,
    )


def _class_recall(run: ComparativeRunResult, cases: tuple[PilotCase, ...]) -> float:
    expected = {item.defect_id for item in cases if item.defect_id is not None}
    matched = {item.defect_id for item in run.benchmark.matches}
    return len(expected & matched) / len(expected) if expected else 1.0


def _trap_rate(run: ComparativeRunResult, cases: tuple[PilotCase, ...]) -> float:
    hit: set[str] = set()
    for finding in run.benchmark.unmatched_predictions:
        if finding.path is None or finding.start_line is None:
            continue
        end = finding.end_line or finding.start_line
        for case in cases:
            if any(_overlaps(region, finding.path, finding.start_line, end) for region in case.regions):
                hit.add(case.case_id)
    return len(hit) / len(cases) if cases else 0.0


def _overlaps(region: PilotRegion, path: str, start: int, end: int) -> bool:
    return region.path == path and region.start_line <= end and start <= region.end_line


def _regions(value: Any) -> tuple[PilotRegion, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("Caller pilot regions must be a non-empty array")
    regions: list[PilotRegion] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            raise ValueError("Caller pilot region must be an object")
        start = _positive_int(raw.get("start_line"), "region.start_line")
        end = _positive_int(raw.get("end_line"), "region.end_line")
        if end < start:
            raise ValueError("Caller pilot region is reversed")
        regions.append(PilotRegion(path=_safe_path(_required_text(raw, "path")), start_line=start, end_line=end))
    return tuple(regions)


def _safe_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Caller pilot path must be repository-relative")
    return candidate.as_posix()


def _required_text(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Caller pilot field {key!r} must be non-empty text")
    return value.strip()


def _positive_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Caller pilot field {key!r} must be a positive integer")
    return value
