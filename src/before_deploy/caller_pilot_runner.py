"""Provider-neutral execution bridge for the blinded `find_callers` pilot."""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from before_deploy.caller_experiment import (
    CALLER_TOOL_NAME,
    CallerClaimDraft,
    CallerExperiment,
    CallerExperimentRun,
    CallerModelInput,
    CallerTurn,
    comparative_finding_evidence,
)
from before_deploy.caller_pilot import (
    CallerPilotAssessment,
    evaluate_caller_pilot,
    load_pilot_definition,
    prepare_initial_evidence,
    render_pilot_json,
    render_pilot_markdown,
)
from before_deploy.comparative_benchmark import (
    COMPARATIVE_BENCHMARK_SCHEMA,
    evaluate_comparative_manifest,
    render_comparative_json,
    render_comparative_markdown,
)

BRIDGE_REQUEST_SCHEMA = "before-deploy-caller-bridge-request-v1"
BRIDGE_RESPONSE_SCHEMA = "before-deploy-caller-bridge-response-v1"

_log = logging.getLogger("before_deploy.caller_pilot_runner")


@dataclass(frozen=True)
class BridgeUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_microusd: int = 0


@dataclass(frozen=True)
class PilotExecutionArtifacts:
    manifest_path: Path
    comparative_json_path: Path
    comparative_markdown_path: Path
    pilot_json_path: Path
    pilot_markdown_path: Path
    assessment: CallerPilotAssessment


class SubprocessCallerModel:
    """Strict JSON bridge to an external model adapter.

    The subprocess receives only blinded evidence plus the single allowed tool
    contract. It receives no case class, defect ID, or evaluator regions.
    """

    def __init__(
        self,
        *,
        command: Sequence[str],
        provider: str,
        model: str,
        enable_find_callers: bool,
        allowed_symbol: str,
        timeout_seconds: int = 60,
    ) -> None:
        self._command = _command(command)
        self._provider = _text(provider, "provider")
        self._model = _text(model, "model")
        self._enable_find_callers = bool(enable_find_callers)
        self._allowed_symbol = _text(allowed_symbol, "allowed_symbol")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")
        self._timeout_seconds = timeout_seconds
        self._input_tokens = 0
        self._output_tokens = 0
        self._cost_microusd = 0

    @property
    def provider_id(self) -> str:
        return self._provider

    @property
    def model_id(self) -> str:
        return self._model

    @property
    def usage(self) -> BridgeUsage:
        return BridgeUsage(
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            cost_microusd=self._cost_microusd,
        )

    def complete(self, request: CallerModelInput) -> CallerTurn:
        _log.debug(
            "bridge call: step=%d provider=%s model=%s",
            request.step, self._provider, self._model,
        )
        payload = _request_payload(
            request,
            provider=self._provider,
            model=self._model,
            enable_find_callers=self._enable_find_callers,
            allowed_symbol=self._allowed_symbol,
        )
        try:
            completed = subprocess.run(
                self._command,
                input=json.dumps(payload, sort_keys=True, ensure_ascii=False),
                text=True,
                capture_output=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError(f"caller bridge execution failed: {type(error).__name__}") from error
        if completed.stderr:
            _log.warning("bridge stderr: %s", completed.stderr[:2000])
        if completed.returncode != 0:
            stderr_hint = (completed.stderr or "")[:2000]
            raise RuntimeError(
                f"caller bridge returned non-zero status: {stderr_hint}"
            )
        try:
            response = json.loads(completed.stdout)
        except ValueError as error:
            raise ValueError("caller bridge stdout must be one JSON object") from error
        turn, usage = _parse_bridge_response(
            response,
            enable_find_callers=self._enable_find_callers,
            allowed_symbol=self._allowed_symbol,
        )
        self._input_tokens += usage.input_tokens
        self._output_tokens += usage.output_tokens
        self._cost_microusd += usage.cost_microusd
        return turn


def execute_caller_pilot(
    *,
    cases_path: Path,
    corpus_path: Path,
    output_dir: Path,
    command: Sequence[str],
    provider: str,
    model: str,
    repetitions: int = 1,
    timeout_seconds: int = 120,
) -> PilotExecutionArtifacts:
    """Run paired static/exploratory variants and emit PR41/PR43 artifacts."""
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions <= 0:
        raise ValueError("repetitions must be a positive integer")
    definition = load_pilot_definition(cases_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    runs: list[dict[str, object]] = []

    variants = (
        ("static", "STATIC", False),
        ("find-callers", "EXPLORATORY", True),
    )
    for repetition in range(1, repetitions + 1):
        for variant, role, enabled in variants:
            findings: list[Mapping[str, object]] = []
            finding_evidence: list[Mapping[str, object]] = []
            seen_fingerprints: set[str] = set()
            context_bytes = 0
            tool_calls = 0
            latency_ms = 0
            input_tokens = 0
            output_tokens = 0
            cost_microusd = 0

            for case_index, case in enumerate(definition.cases, start=1):
                _log.info(
                    "case %d/%d %s/%s rep=%d case=%s",
                    case_index, len(definition.cases),
                    variant, role, repetition, case.case_id,
                )
                repository, prepared_case, evidence = prepare_initial_evidence(cases_path, case.case_id)
                if prepared_case.symbol != case.symbol:
                    raise ValueError("Caller pilot case identity changed during preparation")
                bridge = SubprocessCallerModel(
                    command=command,
                    provider=provider,
                    model=model,
                    enable_find_callers=enabled,
                    allowed_symbol=case.symbol,
                    timeout_seconds=timeout_seconds,
                )
                run = CallerExperiment().run(
                    model=bridge,
                    repository=repository,
                    initial_context=(evidence,),
                    enable_find_callers=enabled,
                )
                _require_completed(run, case.case_id, role)
                usage = bridge.usage
                context_bytes += run.initial_context_bytes + run.expanded_context_bytes
                tool_calls += run.tool_calls
                latency_ms += run.latency_ms
                input_tokens += usage.input_tokens
                output_tokens += usage.output_tokens
                cost_microusd += usage.cost_microusd

                for claim in run.claims:
                    fingerprint = claim.finding.fingerprint
                    if fingerprint in seen_fingerprints:
                        raise ValueError("Duplicate finding fingerprint across caller pilot cases")
                    seen_fingerprints.add(fingerprint)
                    findings.append(_finding_payload(claim.finding))
                finding_evidence.extend(comparative_finding_evidence(run))

            advisory_name = f"{variant}-r{repetition}.json"
            advisory_path = output_dir / advisory_name
            advisory_path.write_text(
                json.dumps(
                    {
                        "source": "before-deploy-caller-experiment",
                        "findings": findings,
                    },
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            _log.info("wrote variant artifact: %s", advisory_name)
            runs.append(
                {
                    "run_id": f"{variant}-r{repetition}",
                    "variant": variant,
                    "variant_role": role,
                    "repetition": repetition,
                    "advisory_file": advisory_name,
                    "provider": _text(provider, "provider"),
                    "model": _text(model, "model"),
                    "context_bytes": context_bytes,
                    "tool_calls": tool_calls,
                    "latency_ms": latency_ms,
                    "cost_microusd": cost_microusd,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "tool_names": [CALLER_TOOL_NAME] if tool_calls else [],
                    "finding_evidence": finding_evidence,
                }
            )

    manifest_path = output_dir / "comparative-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": COMPARATIVE_BENCHMARK_SCHEMA,
                "benchmark": {
                    "name": definition.name,
                    "runs": runs,
                },
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    comparative = evaluate_comparative_manifest(corpus_path, manifest_path)
    assessment = evaluate_caller_pilot(
        corpus_path=corpus_path,
        comparative_manifest_path=manifest_path,
        cases_path=cases_path,
    )

    comparative_json_path = output_dir / "comparative-benchmark.json"
    comparative_markdown_path = output_dir / "comparative-benchmark.md"
    pilot_json_path = output_dir / "caller-pilot.json"
    pilot_markdown_path = output_dir / "caller-pilot.md"
    comparative_json_path.write_text(render_comparative_json(comparative), encoding="utf-8")
    comparative_markdown_path.write_text(render_comparative_markdown(comparative), encoding="utf-8")
    pilot_json_path.write_text(render_pilot_json(assessment), encoding="utf-8")
    pilot_markdown_path.write_text(render_pilot_markdown(assessment), encoding="utf-8")
    return PilotExecutionArtifacts(
        manifest_path=manifest_path,
        comparative_json_path=comparative_json_path,
        comparative_markdown_path=comparative_markdown_path,
        pilot_json_path=pilot_json_path,
        pilot_markdown_path=pilot_markdown_path,
        assessment=assessment,
    )


def _request_payload(
    request: CallerModelInput,
    *,
    provider: str,
    model: str,
    enable_find_callers: bool,
    allowed_symbol: str,
) -> Mapping[str, object]:
    tools: list[Mapping[str, object]] = []
    allowed_actions = ["FINAL"]
    if enable_find_callers:
        allowed_actions.append("FIND_CALLERS")
        tools.append(
            {
                "name": CALLER_TOOL_NAME,
                "description": "Return bounded lexical call sites and nearby context for the supplied symbol.",
                "arguments": {"symbol": allowed_symbol},
            }
        )
    return {
        "schema_version": BRIDGE_REQUEST_SCHEMA,
        "provider": provider,
        "model": model,
        "step": request.step,
        "task": (
            "Review only the supplied evidence for concrete bugs or security issues. "
            "Do not assume repository context that is not present. Return exactly one JSON response "
            "matching the bridge response schema."
        ),
        "authority": "ADVISORY",
        "gate_effect": "NONE",
        "allowed_actions": allowed_actions,
        "tools": tools,
        "initial_context": [
            {
                "evidence_id": item.evidence_id,
                "path": item.path,
                "content_sha256": item.content_sha256,
                "content": item.content,
            }
            for item in request.initial_context
        ],
        "caller_observations": [
            {
                "call_id": item.call_id,
                "symbol": item.symbol,
                "evidence_id": item.evidence_id,
                "content_sha256": item.content_sha256,
                "content": item.content,
            }
            for item in request.caller_observations
        ],
        "response_contract": {
            "schema_version": BRIDGE_RESPONSE_SCHEMA,
            "find_callers": {
                "action": "FIND_CALLERS",
                "call_id": "non-empty unique text",
                "symbol": allowed_symbol,
                "usage": {
                    "input_tokens": "non-negative integer",
                    "output_tokens": "non-negative integer",
                    "cost_microusd": "non-negative integer",
                },
            }
            if enable_find_callers
            else None,
            "final": {
                "action": "FINAL",
                "claims": [
                    {
                        "title": "text",
                        "message": "text",
                        "category": "bug|security|performance|maintainability|test|style|documentation|other",
                        "severity": "critical|high|medium|low|info",
                        "evidence_ids": ["evidence id from this request"],
                        "path": "optional repository-relative path",
                        "start_line": "optional positive integer",
                        "end_line": "optional positive integer",
                        "confidence": "optional text",
                    }
                ],
                "usage": {
                    "input_tokens": "non-negative integer",
                    "output_tokens": "non-negative integer",
                    "cost_microusd": "non-negative integer",
                },
            },
        },
    }


def _parse_bridge_response(
    value: Any,
    *,
    enable_find_callers: bool,
    allowed_symbol: str,
) -> tuple[CallerTurn, BridgeUsage]:
    if not isinstance(value, Mapping) or value.get("schema_version") != BRIDGE_RESPONSE_SCHEMA:
        raise ValueError("Unsupported caller bridge response schema")
    usage = _usage(value.get("usage"))
    action = _text(value.get("action"), "action").upper()
    if action == "FIND_CALLERS":
        if not enable_find_callers:
            raise ValueError("Static caller bridge response requested find_callers")
        symbol = _text(value.get("symbol"), "symbol")
        if symbol != allowed_symbol:
            raise ValueError("Caller bridge requested a symbol outside the blinded case boundary")
        return (
            CallerTurn(
                action="FIND_CALLERS",
                call_id=_text(value.get("call_id"), "call_id"),
                symbol=symbol,
            ),
            usage,
        )
    if action != "FINAL":
        raise ValueError("Caller bridge action must be FINAL or FIND_CALLERS")
    raw_claims = value.get("claims")
    if not isinstance(raw_claims, list):
        raise ValueError("FINAL caller bridge response requires claims array")
    claims = tuple(_claim(item) for item in raw_claims)
    return CallerTurn(action="FINAL", claims=claims), usage


def _claim(value: Any) -> CallerClaimDraft:
    if not isinstance(value, Mapping):
        raise ValueError("Caller bridge claim must be an object")
    raw_ids = value.get("evidence_ids")
    if not isinstance(raw_ids, list) or not raw_ids or not all(
        isinstance(item, str) and item.strip() for item in raw_ids
    ):
        raise ValueError("Caller bridge claim evidence_ids must be non-empty text array")
    start = _optional_positive_int(value.get("start_line"), "start_line")
    end = _optional_positive_int(value.get("end_line"), "end_line")
    return CallerClaimDraft(
        title=_text(value.get("title"), "title"),
        message=_text(value.get("message"), "message"),
        category=_text(value.get("category"), "category"),
        severity=_text(value.get("severity"), "severity"),
        evidence_ids=tuple(item.strip() for item in raw_ids),
        path=_optional_text(value.get("path")),
        start_line=start,
        end_line=end,
        confidence=_optional_text(value.get("confidence")),
    )


def _usage(value: Any) -> BridgeUsage:
    if not isinstance(value, Mapping):
        raise ValueError("Caller bridge response requires usage object")
    return BridgeUsage(
        input_tokens=_nonnegative_int(value.get("input_tokens"), "input_tokens"),
        output_tokens=_nonnegative_int(value.get("output_tokens"), "output_tokens"),
        cost_microusd=_nonnegative_int(value.get("cost_microusd"), "cost_microusd"),
    )


def _finding_payload(finding) -> Mapping[str, object]:
    payload: dict[str, object] = {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "message": finding.message,
        "category": finding.category,
        "severity": finding.severity,
    }
    if finding.confidence is not None:
        payload["confidence"] = finding.confidence
    if finding.location is not None:
        payload["location"] = {
            "path": finding.location.path,
            "start_line": finding.location.start_line,
            "end_line": finding.location.end_line,
        }
    return payload


def _require_completed(run: CallerExperimentRun, case_id: str, role: str) -> None:
    if run.status != "COMPLETED":
        raise RuntimeError(
            f"Caller pilot execution did not complete for case {case_id} role {role}: {run.message}"
        )


def _command(value: Sequence[str]) -> tuple[str, ...]:
    items = tuple(value)
    if not items or not all(isinstance(item, str) and item.strip() for item in items):
        raise ValueError("bridge command must be a non-empty sequence of strings")
    return tuple(item.strip() for item in items)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Optional caller bridge text field must be text")
    normalized = value.strip()
    return normalized or None


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _optional_positive_int(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value
