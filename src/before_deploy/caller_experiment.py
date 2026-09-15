"""Minimal advisory experiment loop exposing only deterministic `find_callers`."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from pathlib import Path
from time import perf_counter_ns
from typing import Mapping, Protocol, Sequence

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport
from before_deploy.comparative_benchmark import DEPENDENCY_EXPANDED, DEPENDENCY_INITIAL
from before_deploy.inventory import collect_inventory
from before_deploy.models import Location

CALLER_EXPERIMENT_SCHEMA = "before-deploy-caller-experiment-v1"
CALLER_EXPERIMENT_AUTHORITY = "AI_DISCOVERY_ADVISORY"
CALLER_EXPERIMENT_GATE_EFFECT = "NONE"
CALLER_TOOL_NAME = "find_callers"

_ALLOWED_ACTIONS = {"FIND_CALLERS", "FINAL"}
_ALLOWED_CATEGORIES = {
    "bug",
    "security",
    "performance",
    "maintainability",
    "test",
    "style",
    "documentation",
    "other",
}
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass(frozen=True)
class CallerBudget:
    max_steps: int = 4
    max_tool_calls: int = 3
    max_results_per_call: int = 40
    max_result_bytes: int = 64_000
    max_duration_ms: int = 60_000
    max_file_bytes: int = 1_000_000
    max_index_files: int = 5_000
    max_index_bytes: int = 32_000_000

    def validate(self) -> None:
        for name, value in self.__dict__.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"Caller experiment budget {name} must be positive")


@dataclass(frozen=True)
class InitialEvidence:
    evidence_id: str
    path: str
    content: str
    content_sha256: str

    @classmethod
    def from_text(cls, *, evidence_id: str, path: str, content: str) -> "InitialEvidence":
        if not evidence_id.strip() or not path.strip():
            raise ValueError("Initial caller evidence identity/path must be non-empty")
        return cls(
            evidence_id=evidence_id,
            path=path,
            content=content,
            content_sha256=sha256(content.encode("utf-8")).hexdigest(),
        )


@dataclass(frozen=True)
class CallerObservation:
    call_id: str
    symbol: str
    evidence_id: str
    content: str
    content_sha256: str
    size_bytes: int
    result_count: int
    truncated: bool


@dataclass(frozen=True)
class CallerClaimDraft:
    title: str
    message: str
    category: str
    severity: str
    evidence_ids: tuple[str, ...]
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    confidence: str | None = None


@dataclass(frozen=True)
class CallerTurn:
    action: str
    call_id: str | None = None
    symbol: str | None = None
    claims: tuple[CallerClaimDraft, ...] = ()


@dataclass(frozen=True)
class CallerModelInput:
    step: int
    initial_context: tuple[InitialEvidence, ...]
    caller_observations: tuple[CallerObservation, ...]


@dataclass(frozen=True)
class CallerClaim:
    finding: AdvisoryFinding
    evidence_ids: tuple[str, ...]
    evidence_dependency: str
    supported_claim: bool = True
    citation_correct: bool = True


@dataclass(frozen=True)
class CallerExperimentRun:
    provider: str
    model: str
    status: str
    initial_context_bytes: int
    expanded_context_bytes: int
    tool_calls: int
    latency_ms: int
    observations: tuple[CallerObservation, ...]
    claims: tuple[CallerClaim, ...]
    message: str | None = None
    schema_version: str = CALLER_EXPERIMENT_SCHEMA
    authority: str = CALLER_EXPERIMENT_AUTHORITY
    gate_effect: str = CALLER_EXPERIMENT_GATE_EFFECT


class CallerModel(Protocol):
    @property
    def provider_id(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    def complete(self, request: CallerModelInput) -> CallerTurn: ...


class FindCallersIndex:
    """Bounded lexical call-site index. It makes no runtime-reachability claim."""

    def __init__(self, repository: Path, *, budget: CallerBudget | None = None) -> None:
        self.budget = budget or CallerBudget()
        self.budget.validate()
        inventory = collect_inventory(repository, max_file_bytes=self.budget.max_file_bytes)
        files: list[tuple[str, tuple[str, ...]]] = []
        total_bytes = 0
        for source in inventory.files:
            if len(files) >= self.budget.max_index_files:
                break
            try:
                raw = source.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if total_bytes + len(raw) > self.budget.max_index_bytes:
                continue
            files.append((source.relative_to(inventory.root).as_posix(), tuple(text.splitlines())))
            total_bytes += len(raw)
        self.files = tuple(files)

    def find_callers(self, *, call_id: str, symbol: str) -> CallerObservation:
        if not call_id.strip():
            raise ValueError("find_callers call_id must be non-empty")
        symbol = _symbol(symbol)
        call_pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(")
        definition_patterns = (
            re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(symbol)}\s*\("),
            re.compile(rf"^\s*(?:export\s+)?(?:async\s+)?function\s+{re.escape(symbol)}\s*\("),
            re.compile(rf"^\s*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(symbol)}\s*\("),
            re.compile(rf"^\s*func\s+(?:\([^)]*\)\s*)?{re.escape(symbol)}\s*\("),
        )
        matches: list[dict[str, object]] = []
        for path, lines in self.files:
            for line_number, text in enumerate(lines, start=1):
                if not call_pattern.search(text):
                    continue
                if any(pattern.search(text) for pattern in definition_patterns):
                    continue
                matches.append({"path": path, "line": line_number, "text": text.strip()})
        matches.sort(key=lambda item: (str(item["path"]), int(item["line"])))
        selected = matches[: self.budget.max_results_per_call]
        payload = {
            "tool": CALLER_TOOL_NAME,
            "symbol": symbol,
            "semantics": "lexical_static_call_sites_not_runtime_reachability",
            "call_sites": selected,
            "truncated_by_count": len(matches) > len(selected),
        }
        content = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        encoded = content.encode("utf-8")
        truncated = len(matches) > len(selected)
        if len(encoded) > self.budget.max_result_bytes:
            payload = {
                "tool": CALLER_TOOL_NAME,
                "symbol": symbol,
                "semantics": "lexical_static_call_sites_not_runtime_reachability",
                "truncated_by_bytes": True,
                "original_sha256": sha256(encoded).hexdigest(),
                "original_size_bytes": len(encoded),
            }
            content = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            encoded = content.encode("utf-8")
            truncated = True
        digest = sha256(encoded).hexdigest()
        return CallerObservation(
            call_id=call_id,
            symbol=symbol,
            evidence_id=f"find-callers:{digest}",
            content=content,
            content_sha256=digest,
            size_bytes=len(encoded),
            result_count=len(selected),
            truncated=truncated,
        )


class CallerExperiment:
    def __init__(self, *, budget: CallerBudget | None = None) -> None:
        self.budget = budget or CallerBudget()
        self.budget.validate()

    def run(
        self,
        *,
        model: CallerModel,
        repository: Path,
        initial_context: Sequence[InitialEvidence],
        enable_find_callers: bool,
    ) -> CallerExperimentRun:
        provider = _identity(model.provider_id, "provider_id")
        model_id = _identity(model.model_id, "model_id")
        context = _validate_initial_context(initial_context)
        index = FindCallersIndex(repository, budget=self.budget) if enable_find_callers else None
        allowed_evidence = {item.evidence_id for item in context}
        observations: list[CallerObservation] = []
        started = perf_counter_ns()
        message: str | None = None
        status = "ERROR"
        claims: tuple[CallerClaim, ...] = ()

        try:
            for step in range(1, self.budget.max_steps + 1):
                if _elapsed_ms(started) >= self.budget.max_duration_ms:
                    status = "BUDGET_EXHAUSTED"
                    message = "duration_budget_exhausted"
                    break
                turn = model.complete(
                    CallerModelInput(
                        step=step,
                        initial_context=context,
                        caller_observations=tuple(observations),
                    )
                )
                _validate_turn(turn)
                if turn.action == "FINAL":
                    claims = _normalize_claims(turn.claims, allowed_evidence, observations)
                    status = "COMPLETED"
                    break
                if not enable_find_callers or index is None:
                    status = "ERROR"
                    message = "find_callers_not_enabled_for_static_variant"
                    break
                if len(observations) >= self.budget.max_tool_calls:
                    status = "BUDGET_EXHAUSTED"
                    message = "tool_call_budget_exhausted"
                    break
                observation = index.find_callers(call_id=turn.call_id or "", symbol=turn.symbol or "")
                observations.append(observation)
                allowed_evidence.add(observation.evidence_id)
            else:
                status = "BUDGET_EXHAUSTED"
                message = "step_budget_exhausted"
        except Exception as error:
            status = "ERROR"
            message = f"caller_experiment_failed:{type(error).__name__}"

        return CallerExperimentRun(
            provider=provider,
            model=model_id,
            status=status,
            initial_context_bytes=sum(len(item.content.encode("utf-8")) for item in context),
            expanded_context_bytes=sum(item.size_bytes for item in observations),
            tool_calls=len(observations),
            latency_ms=_elapsed_ms(started),
            observations=tuple(observations),
            claims=claims if status == "COMPLETED" else (),
            message=message,
        )


def advisory_import_from_caller_run(run: CallerExperimentRun) -> AdvisoryImport:
    return AdvisoryImport(
        input_name="caller-experiment",
        source="before-deploy-caller-experiment",
        source_format=CALLER_EXPERIMENT_SCHEMA,
        findings=tuple(item.finding for item in run.claims),
        status="COMPLETED" if run.status == "COMPLETED" else "ERROR",
        message=run.message,
        scope_status="MATCHED",
        scope_message=(
            f"find_callers_calls={run.tool_calls} expanded_context_bytes={run.expanded_context_bytes}"
        ),
    )


def comparative_finding_evidence(run: CallerExperimentRun) -> tuple[Mapping[str, object], ...]:
    """Return PR41-compatible attribution; dependency is derived, never model-authored."""
    return tuple(
        {
            "fingerprint": item.finding.fingerprint,
            "evidence_dependency": item.evidence_dependency,
            "supported_claim": item.supported_claim,
            "citation_correct": item.citation_correct,
        }
        for item in run.claims
    )


def _normalize_claims(
    drafts: Sequence[CallerClaimDraft],
    allowed_evidence: set[str],
    observations: Sequence[CallerObservation],
) -> tuple[CallerClaim, ...]:
    expanded_ids = {item.evidence_id for item in observations}
    claims: list[CallerClaim] = []
    for draft in drafts:
        title = _text(draft.title, "title", 300)
        message = _text(draft.message, "message", 8_000)
        category = draft.category.strip().lower()
        severity = draft.severity.strip().lower()
        if category not in _ALLOWED_CATEGORIES or severity not in _ALLOWED_SEVERITIES:
            raise ValueError("Unsupported caller experiment category/severity")
        evidence_ids = tuple(sorted(set(draft.evidence_ids)))
        if not evidence_ids or not set(evidence_ids) <= allowed_evidence:
            raise ValueError("Caller claim cites evidence outside the execution trace")
        path = draft.path.strip().replace("\\", "/") if draft.path else None
        if path and (path.startswith("/") or ".." in Path(path).parts):
            raise ValueError("Caller claim path must be repository-relative")
        start, end = _lines(draft.start_line, draft.end_line, path)
        fingerprint_payload = {
            "source": "before-deploy-caller-experiment",
            "title": title,
            "message": message,
            "category": category,
            "severity": severity,
            "location": None
            if path is None
            else {"path": path, "start_line": start, "end_line": end},
        }
        fingerprint = sha256(
            dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        finding = AdvisoryFinding(
            finding_id=f"CALLER-{fingerprint[:12]}",
            source="before-deploy-caller-experiment",
            title=title,
            message=message,
            category=category,
            severity=severity,
            confidence=draft.confidence.strip() if draft.confidence else None,
            fingerprint=fingerprint,
            location=Location(path=path, start_line=start, end_line=end) if path else None,
        )
        claims.append(
            CallerClaim(
                finding=finding,
                evidence_ids=evidence_ids,
                evidence_dependency=(
                    DEPENDENCY_EXPANDED if set(evidence_ids) & expanded_ids else DEPENDENCY_INITIAL
                ),
            )
        )
    return tuple(claims)


def _validate_initial_context(items: Sequence[InitialEvidence]) -> tuple[InitialEvidence, ...]:
    values = tuple(items)
    seen: set[str] = set()
    for item in values:
        if item.evidence_id in seen:
            raise ValueError("Duplicate initial evidence ID")
        if sha256(item.content.encode("utf-8")).hexdigest() != item.content_sha256:
            raise ValueError("Initial evidence content hash mismatch")
        seen.add(item.evidence_id)
    return values


def _validate_turn(turn: CallerTurn) -> None:
    if not isinstance(turn, CallerTurn) or turn.action not in _ALLOWED_ACTIONS:
        raise ValueError("Unsupported caller model turn")
    if turn.action == "FIND_CALLERS":
        if turn.claims or not turn.call_id or not turn.symbol:
            raise ValueError("FIND_CALLERS requires call_id/symbol and no final claims")
    elif turn.call_id is not None or turn.symbol is not None:
        raise ValueError("FINAL cannot contain a tool request")


def _symbol(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value.strip()):
        raise ValueError("find_callers symbol must be a simple identifier")
    return value.strip()


def _identity(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Caller experiment {label} must be non-empty")
    return value.strip()


def _text(value: str, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"Caller claim {label} is invalid")
    return value.strip()


def _lines(start: int | None, end: int | None, path: str | None) -> tuple[int | None, int | None]:
    if path is None:
        if start is not None or end is not None:
            raise ValueError("Caller claim lines require a path")
        return None, None
    if start is None:
        return None, None if end is None else end
    if isinstance(start, bool) or not isinstance(start, int) or start <= 0:
        raise ValueError("Caller claim start_line must be positive")
    actual_end = start if end is None else end
    if isinstance(actual_end, bool) or not isinstance(actual_end, int) or actual_end < start:
        raise ValueError("Caller claim end_line must be >= start_line")
    return start, actual_end


def _elapsed_ms(started_ns: int) -> int:
    return max(0, (perf_counter_ns() - started_ns) // 1_000_000)
