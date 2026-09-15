"""Full gate-neutral comparison across discovery, challenge, and verification layers."""

from __future__ import annotations

from dataclasses import dataclass
from json import dumps
from typing import Sequence

from before_deploy.comparative_benchmark import ComparativeBenchmarkResult

FULL_COMPARISON_SCHEMA = "before-deploy-full-assurance-comparison-v1"
FULL_COMPARISON_AUTHORITY = "BENCHMARK_DIAGNOSTIC"
FULL_COMPARISON_GATE_EFFECT = "NONE"


@dataclass(frozen=True)
class VariantAssuranceSupplement:
    variant: str
    challenges_supported: int = 0
    challenges_insufficient: int = 0
    challenges_contradicted: int = 0
    challenges_unresolved: int = 0
    obligations_proposed: int = 0
    obligations_frozen: int = 0
    verification_pass: int = 0
    verification_fail: int = 0
    verification_error: int = 0


@dataclass(frozen=True)
class FullComparisonVariant:
    variant: str
    variant_role: str
    run_count: int
    mean_precision: float
    mean_recall: float
    mean_f1: float
    exploration_attributable_tp: int
    exploration_attributable_fp: int
    prediction_stability: float
    mean_tool_calls: float
    mean_context_bytes: float
    mean_latency_ms: float
    mean_cost_microusd: float
    challenges_supported: int
    challenges_insufficient: int
    challenges_contradicted: int
    challenges_unresolved: int
    obligations_proposed: int
    obligations_frozen: int
    obligation_freeze_rate: float | None
    verification_pass: int
    verification_fail: int
    verification_error: int
    verification_pass_rate: float | None


@dataclass(frozen=True)
class FullAssuranceComparison:
    name: str
    variants: tuple[FullComparisonVariant, ...]
    schema_version: str = FULL_COMPARISON_SCHEMA
    authority: str = FULL_COMPARISON_AUTHORITY
    gate_effect: str = FULL_COMPARISON_GATE_EFFECT


def build_full_assurance_comparison(
    comparative: ComparativeBenchmarkResult,
    supplements: Sequence[VariantAssuranceSupplement],
) -> FullAssuranceComparison:
    """Join PR41 discovery metrics with later challenge/verification diagnostics."""
    supplement_by_variant: dict[str, VariantAssuranceSupplement] = {}
    for item in supplements:
        variant = _text(item.variant, "supplement variant")
        if variant in supplement_by_variant:
            raise ValueError(f"Duplicate full-comparison supplement for variant {variant!r}")
        _validate_counts(item)
        supplement_by_variant[variant] = item

    variants = {item.variant for item in comparative.variants}
    if variants != set(supplement_by_variant):
        missing = sorted(variants - set(supplement_by_variant))
        extra = sorted(set(supplement_by_variant) - variants)
        raise ValueError(f"Full comparison supplement mismatch: missing={missing}, extra={extra}")

    rows = []
    for aggregate in comparative.variants:
        supplement = supplement_by_variant[aggregate.variant]
        verification_total = (
            supplement.verification_pass
            + supplement.verification_fail
            + supplement.verification_error
        )
        rows.append(
            FullComparisonVariant(
                variant=aggregate.variant,
                variant_role=aggregate.variant_role,
                run_count=aggregate.run_count,
                mean_precision=aggregate.mean_precision,
                mean_recall=aggregate.mean_recall,
                mean_f1=aggregate.mean_f1,
                exploration_attributable_tp=aggregate.exploration_attributable_tp,
                exploration_attributable_fp=aggregate.exploration_attributable_fp,
                prediction_stability=aggregate.prediction_stability,
                mean_tool_calls=aggregate.mean_tool_calls,
                mean_context_bytes=aggregate.mean_context_bytes,
                mean_latency_ms=aggregate.mean_latency_ms,
                mean_cost_microusd=aggregate.mean_cost_microusd,
                challenges_supported=supplement.challenges_supported,
                challenges_insufficient=supplement.challenges_insufficient,
                challenges_contradicted=supplement.challenges_contradicted,
                challenges_unresolved=supplement.challenges_unresolved,
                obligations_proposed=supplement.obligations_proposed,
                obligations_frozen=supplement.obligations_frozen,
                obligation_freeze_rate=(
                    supplement.obligations_frozen / supplement.obligations_proposed
                    if supplement.obligations_proposed
                    else None
                ),
                verification_pass=supplement.verification_pass,
                verification_fail=supplement.verification_fail,
                verification_error=supplement.verification_error,
                verification_pass_rate=(
                    supplement.verification_pass / verification_total
                    if verification_total
                    else None
                ),
            )
        )
    return FullAssuranceComparison(name=comparative.name, variants=tuple(rows))


def render_full_assurance_comparison_json(result: FullAssuranceComparison) -> str:
    payload = {
        "schema_version": result.schema_version,
        "full_assurance_comparison": {
            "name": result.name,
            "authority": result.authority,
            "gate_effect": result.gate_effect,
            "variants": [
                {
                    field: getattr(item, field)
                    for field in FullComparisonVariant.__dataclass_fields__
                }
                for item in result.variants
            ],
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_full_assurance_comparison_markdown(result: FullAssuranceComparison) -> str:
    lines = [
        "# Before Deploy Full Assurance Comparison",
        "",
        f"- Experiment: `{result.name}`",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        "",
        "| Variant | Role | Precision | Recall | F1 | Explore TP | Explore FP | Stability | Challenge S/I/C/U | Frozen/Proposed | Verify P/F/E | Mean tools | Mean latency ms | Mean cost µUSD |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|---:|---|---:|---:|---:|",
    ]
    for item in result.variants:
        lines.append(
            f"| {item.variant} | {item.variant_role} | {item.mean_precision:.4f} | "
            f"{item.mean_recall:.4f} | {item.mean_f1:.4f} | "
            f"{item.exploration_attributable_tp} | {item.exploration_attributable_fp} | "
            f"{item.prediction_stability:.4f} | "
            f"{item.challenges_supported}/{item.challenges_insufficient}/{item.challenges_contradicted}/{item.challenges_unresolved} | "
            f"{item.obligations_frozen}/{item.obligations_proposed} | "
            f"{item.verification_pass}/{item.verification_fail}/{item.verification_error} | "
            f"{item.mean_tool_calls:.2f} | {item.mean_latency_ms:.2f} | {item.mean_cost_microusd:.2f} |"
        )
    lines.extend(
        [
            "",
            "> This table is experimental diagnostics only. Challenge and verification metrics do not alter deterministic release disposition.",
        ]
    )
    return "\n".join(lines) + "\n"


def _validate_counts(item: VariantAssuranceSupplement) -> None:
    fields = (
        "challenges_supported",
        "challenges_insufficient",
        "challenges_contradicted",
        "challenges_unresolved",
        "obligations_proposed",
        "obligations_frozen",
        "verification_pass",
        "verification_fail",
        "verification_error",
    )
    for field in fields:
        value = getattr(item, field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Full comparison {field} must be a non-negative integer")
    if item.obligations_frozen > item.obligations_proposed:
        raise ValueError("Frozen verification obligations cannot exceed proposals")
    result_count = item.verification_pass + item.verification_fail + item.verification_error
    if result_count > item.obligations_frozen:
        raise ValueError("Verification results cannot exceed frozen obligations")


def _text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    return value.strip()
