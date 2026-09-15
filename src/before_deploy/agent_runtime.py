"""Bounded, evidence-cited runtime for native AI discovery.

This module is deliberately independent from deterministic policy and release disposition.
Models may request bounded tools and return advisory claims, but they cannot create waivers,
approvals, verification status, policy decisions, or release dispositions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from json import dumps
from time import perf_counter_ns
from typing import Any, Mapping, Protocol, Sequence

AGENT_RUN_SCHEMA_VERSION = "before-deploy-agent-run-v1"
AGENT_AUTHORITY = "AI_DISCOVERY_ADVISORY"
AGENT_GATE_EFFECT = "NONE"
AGENT_RELEASE_STATUS = "NOT_EVALUATED"

_ALLOWED_ACTIONS = {"TOOL", "FINAL"}
_ALLOWED_TOOL_STATUSES = {"OK", "ERROR", "DENIED"}
_ALLOWED_RUN_STATUSES = {"COMPLETED", "BUDGET_EXHAUSTED", "ERROR"}
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
class AgentBudget:
    """Hard runtime budgets. A zero/negative value is never interpreted as unlimited."""

    max_steps: int = 12
    max_tool_calls: int = 32
    max_tool_result_bytes: int = 262_144
    max_input_tokens: int = 120_000
    max_output_tokens: int = 24_000
    max_cost_microusd: int = 2_000_000
    max_duration_ms: int = 180_000

    def validate(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"Agent budget {name} must be a positive integer")


@dataclass(frozen=True)
class AgentUsage:
    """Usage reported by a provider for one model turn."""

    input_tokens: int = 0
    output_tokens: int = 0
    cost_microusd: int = 0

    def validate(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"Agent usage {name} must be a non-negative integer")

    def plus(self, other: "AgentUsage") -> "AgentUsage":
        return AgentUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cost_microusd=self.cost_microusd + other.cost_microusd,
        )


@dataclass(frozen=True)
class AgentContextItem:
    """One deterministic starting-context item exposed to the model."""

    evidence_id: str
    kind: str
    path: str | None
    content: str
    content_sha256: str

    @classmethod
    def from_text(
        cls,
        *,
        evidence_id: str,
        kind: str,
        content: str,
        path: str | None = None,
    ) -> "AgentContextItem":
        if not evidence_id.strip() or not kind.strip():
            raise ValueError("Agent context identity and kind must be non-empty")
        return cls(
            evidence_id=evidence_id,
            kind=kind,
            path=path,
            content=content,
            content_sha256=sha256(content.encode("utf-8")).hexdigest(),
        )


@dataclass(frozen=True)
class AgentToolRequest:
    call_id: str
    tool_name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class AgentToolResult:
    """A bounded tool observation. `content` is evidence, never authority."""

    call_id: str
    tool_name: str
    status: str
    content: str
    content_sha256: str
    size_bytes: int
    evidence_id: str
    truncated: bool = False
    message: str | None = None

    @classmethod
    def from_text(
        cls,
        *,
        call_id: str,
        tool_name: str,
        status: str,
        content: str,
        truncated: bool = False,
        message: str | None = None,
    ) -> "AgentToolResult":
        encoded = content.encode("utf-8")
        digest = sha256(encoded).hexdigest()
        return cls(
            call_id=call_id,
            tool_name=tool_name,
            status=status,
            content=content,
            content_sha256=digest,
            size_bytes=len(encoded),
            evidence_id=f"agent-tool:{digest}",
            truncated=truncated,
            message=message,
        )

    def validate(self, *, max_bytes: int) -> None:
        if self.status not in _ALLOWED_TOOL_STATUSES:
            raise ValueError(f"Unsupported agent tool status: {self.status!r}")
        if not self.call_id.strip() or not self.tool_name.strip():
            raise ValueError("Agent tool result identity must be non-empty")
        encoded = self.content.encode("utf-8")
        if len(encoded) != self.size_bytes or self.size_bytes > max_bytes:
            raise ValueError("Agent tool result size does not match the bounded content")
        digest = sha256(encoded).hexdigest()
        if digest != self.content_sha256 or self.evidence_id != f"agent-tool:{digest}":
            raise ValueError("Agent tool result content identity mismatch")


@dataclass(frozen=True)
class AgentClaimDraft:
    """Provider-authored advisory claim before Before Deploy assigns a stable ID."""

    title: str
    message: str
    category: str
    severity: str
    confidence: str | None
    evidence_ids: tuple[str, ...]
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    assumptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentClaim:
    """Canonical normalized advisory claim."""

    claim_id: str
    title: str
    message: str
    category: str
    severity: str
    confidence: str | None
    evidence_ids: tuple[str, ...]
    path: str | None
    start_line: int | None
    end_line: int | None
    assumptions: tuple[str, ...]
    authority: str = AGENT_AUTHORITY
    gate_effect: str = AGENT_GATE_EFFECT


@dataclass(frozen=True)
class AgentModelTurn:
    """One structured provider response. Free-form chain-of-thought is never required."""

    action: str
    tool_requests: tuple[AgentToolRequest, ...] = ()
    claims: tuple[AgentClaimDraft, ...] = ()
    usage: AgentUsage = field(default_factory=AgentUsage)
    summary: str | None = None


@dataclass(frozen=True)
class AgentModelInput:
    """Provider-neutral turn input."""

    specialist: str
    objective: str
    step: int
    budget: AgentBudget
    context: tuple[AgentContextItem, ...]
    tool_results: tuple[AgentToolResult, ...]
    prior_summaries: tuple[str, ...]


@dataclass(frozen=True)
class AgentRun:
    schema_version: str
    specialist: str
    provider_id: str
    model_id: str
    objective: str
    status: str
    budget: AgentBudget
    usage: AgentUsage
    steps: int
    tool_calls: int
    duration_ms: int
    context_sha256: str
    tool_result_sha256s: tuple[str, ...]
    claims: tuple[AgentClaim, ...]
    message: str | None
    run_sha256: str
    authority: str = AGENT_AUTHORITY
    gate_effect: str = AGENT_GATE_EFFECT
    release_status: str = AGENT_RELEASE_STATUS


class AgentModel(Protocol):
    """A model adapter. Implementations return only structured turns."""

    @property
    def provider_id(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    def complete(self, request: AgentModelInput) -> AgentModelTurn: ...


class AgentToolExecutor(Protocol):
    """Deterministic mediator for repository/evidence tools."""

    def execute(self, request: AgentToolRequest, *, max_bytes: int) -> AgentToolResult: ...


class AgentRuntime:
    """Execute a bounded iterative discovery loop without release authority."""

    def __init__(self, *, budget: AgentBudget | None = None) -> None:
        self.budget = budget or AgentBudget()
        self.budget.validate()

    def run(
        self,
        *,
        model: AgentModel,
        tools: AgentToolExecutor,
        specialist: str,
        objective: str,
        context: Sequence[AgentContextItem],
    ) -> AgentRun:
        if not specialist.strip() or not objective.strip():
            raise ValueError("Agent specialist and objective must be non-empty")
        provider_id = _clean_identity(model.provider_id, "provider_id")
        model_id = _clean_identity(model.model_id, "model_id")
        context_items = _validate_context(context)
        context_digest = _context_sha256(context_items)
        allowed_evidence = {item.evidence_id for item in context_items}

        usage = AgentUsage()
        tool_results: list[AgentToolResult] = []
        summaries: list[str] = []
        started_ns = perf_counter_ns()
        status = "ERROR"
        message: str | None = None
        claims: tuple[AgentClaim, ...] = ()
        steps = 0

        try:
            for step in range(1, self.budget.max_steps + 1):
                steps = step
                if self._duration_ms(started_ns) >= self.budget.max_duration_ms:
                    status = "BUDGET_EXHAUSTED"
                    message = "Agent duration budget exhausted before model turn"
                    break

                turn = model.complete(
                    AgentModelInput(
                        specialist=specialist,
                        objective=objective,
                        step=step,
                        budget=self.budget,
                        context=context_items,
                        tool_results=tuple(tool_results),
                        prior_summaries=tuple(summaries),
                    )
                )
                _validate_turn(turn)
                usage = usage.plus(turn.usage)
                exceeded = _usage_budget_exceeded(usage, self.budget)
                if exceeded is not None:
                    status = "BUDGET_EXHAUSTED"
                    message = exceeded
                    break
                if turn.summary:
                    summaries.append(_bounded_summary(turn.summary))

                if turn.action == "FINAL":
                    claims = _normalize_claims(turn.claims, allowed_evidence)
                    status = "COMPLETED"
                    break

                for request in turn.tool_requests:
                    if len(tool_results) >= self.budget.max_tool_calls:
                        status = "BUDGET_EXHAUSTED"
                        message = "Agent tool-call budget exhausted"
                        break
                    if self._duration_ms(started_ns) >= self.budget.max_duration_ms:
                        status = "BUDGET_EXHAUSTED"
                        message = "Agent duration budget exhausted during tool execution"
                        break
                    result = tools.execute(
                        request,
                        max_bytes=self.budget.max_tool_result_bytes,
                    )
                    if result.call_id != request.call_id or result.tool_name != request.tool_name:
                        raise ValueError("Agent tool result identity does not match the request")
                    result.validate(max_bytes=self.budget.max_tool_result_bytes)
                    tool_results.append(result)
                    allowed_evidence.add(result.evidence_id)
                if status == "BUDGET_EXHAUSTED":
                    break
            else:
                status = "BUDGET_EXHAUSTED"
                message = "Agent step budget exhausted without a final response"
        except Exception as error:
            status = "ERROR"
            message = f"Agent runtime failed: {type(error).__name__}"

        duration_ms = self._duration_ms(started_ns)
        return _build_run(
            specialist=specialist,
            provider_id=provider_id,
            model_id=model_id,
            objective=objective,
            status=status,
            budget=self.budget,
            usage=usage,
            steps=steps,
            tool_results=tuple(tool_results),
            duration_ms=duration_ms,
            context_sha256=context_digest,
            claims=claims if status == "COMPLETED" else (),
            message=message,
        )

    @staticmethod
    def _duration_ms(started_ns: int) -> int:
        return max(0, (perf_counter_ns() - started_ns) // 1_000_000)


def _validate_context(context: Sequence[AgentContextItem]) -> tuple[AgentContextItem, ...]:
    items = tuple(context)
    seen: set[str] = set()
    for item in items:
        if not item.evidence_id.strip() or not item.kind.strip():
            raise ValueError("Agent context identity and kind must be non-empty")
        digest = sha256(item.content.encode("utf-8")).hexdigest()
        if item.content_sha256 != digest:
            raise ValueError("Agent context content hash mismatch")
        if item.evidence_id in seen:
            raise ValueError(f"Duplicate agent context evidence ID: {item.evidence_id}")
        seen.add(item.evidence_id)
    return items


def _validate_turn(turn: AgentModelTurn) -> None:
    if not isinstance(turn, AgentModelTurn):
        raise ValueError("Agent model returned an unsupported turn type")
    if turn.action not in _ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported agent action: {turn.action!r}")
    turn.usage.validate()
    if turn.action == "TOOL":
        if not turn.tool_requests or turn.claims:
            raise ValueError("TOOL turns require requests and cannot contain final claims")
        call_ids: set[str] = set()
        for request in turn.tool_requests:
            if not request.call_id.strip() or not request.tool_name.strip():
                raise ValueError("Agent tool request identity must be non-empty")
            if request.call_id in call_ids:
                raise ValueError("Duplicate tool call ID in one model turn")
            if not isinstance(request.arguments, Mapping):
                raise ValueError("Agent tool request arguments must be an object")
            call_ids.add(request.call_id)
    elif turn.tool_requests:
        raise ValueError("FINAL turns cannot request additional tools")


def _normalize_claims(
    drafts: Sequence[AgentClaimDraft],
    allowed_evidence: set[str],
) -> tuple[AgentClaim, ...]:
    normalized: dict[str, AgentClaim] = {}
    for draft in drafts:
        title = _bounded_text(draft.title, "claim title", 300)
        message = _bounded_text(draft.message, "claim message", 8_000)
        category = draft.category.strip().lower()
        severity = draft.severity.strip().lower()
        if category not in _ALLOWED_CATEGORIES:
            raise ValueError(f"Unsupported advisory claim category: {category!r}")
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"Unsupported advisory claim severity: {severity!r}")
        evidence_ids = tuple(sorted(set(draft.evidence_ids)))
        if not evidence_ids:
            raise ValueError("Every agent claim must cite at least one evidence item")
        unknown = set(evidence_ids) - allowed_evidence
        if unknown:
            raise ValueError("Agent claim cited evidence outside the bounded execution trace")
        path = _normalize_path(draft.path)
        start_line, end_line = _normalize_lines(draft.start_line, draft.end_line, path)
        assumptions = tuple(
            sorted({_bounded_text(item, "claim assumption", 1_000) for item in draft.assumptions})
        )
        payload = {
            "title": title,
            "message": message,
            "category": category,
            "severity": severity,
            "confidence": draft.confidence,
            "evidence_ids": evidence_ids,
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "assumptions": assumptions,
        }
        digest = _canonical_sha256(payload)
        normalized[digest] = AgentClaim(
            claim_id=f"agent-claim:{digest}",
            title=title,
            message=message,
            category=category,
            severity=severity,
            confidence=_normalize_confidence(draft.confidence),
            evidence_ids=evidence_ids,
            path=path,
            start_line=start_line,
            end_line=end_line,
            assumptions=assumptions,
        )
    return tuple(normalized[key] for key in sorted(normalized))


def _normalize_path(value: str | None) -> str | None:
    if value is None:
        return None
    path = value.strip().replace("\\", "/")
    if not path or path.startswith("/") or ".." in path.split("/"):
        raise ValueError("Agent claim path must be canonical repository-relative text")
    if len(path) >= 3 and path[1:3] == ":/":
        raise ValueError("Agent claim path must not be an absolute drive path")
    if any(part in {"", "."} for part in path.split("/")):
        raise ValueError("Agent claim path must be canonical repository-relative text")
    return path


def _normalize_lines(
    start_line: int | None,
    end_line: int | None,
    path: str | None,
) -> tuple[int | None, int | None]:
    if path is None and (start_line is not None or end_line is not None):
        raise ValueError("Agent claim lines require a repository-relative path")
    if start_line is None and end_line is None:
        return None, None
    if start_line is None:
        start_line = end_line
    if end_line is None:
        end_line = start_line
    assert start_line is not None and end_line is not None
    if isinstance(start_line, bool) or isinstance(end_line, bool):
        raise ValueError("Agent claim line numbers must be positive integers")
    if start_line <= 0 or end_line < start_line:
        raise ValueError("Agent claim line range is invalid")
    return start_line, end_line


def _normalize_confidence(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    return _bounded_text(text, "claim confidence", 100)


def _build_run(
    *,
    specialist: str,
    provider_id: str,
    model_id: str,
    objective: str,
    status: str,
    budget: AgentBudget,
    usage: AgentUsage,
    steps: int,
    tool_results: tuple[AgentToolResult, ...],
    duration_ms: int,
    context_sha256: str,
    claims: tuple[AgentClaim, ...],
    message: str | None,
) -> AgentRun:
    if status not in _ALLOWED_RUN_STATUSES:
        raise ValueError(f"Unsupported agent run status: {status!r}")
    payload = {
        "schema_version": AGENT_RUN_SCHEMA_VERSION,
        "specialist": specialist,
        "provider_id": provider_id,
        "model_id": model_id,
        "objective": objective,
        "status": status,
        "budget": budget.__dict__,
        "usage": usage.__dict__,
        "steps": steps,
        "tool_calls": len(tool_results),
        "duration_ms": duration_ms,
        "context_sha256": context_sha256,
        "tool_result_sha256s": tuple(result.content_sha256 for result in tool_results),
        "claims": tuple(_claim_primitive(claim) for claim in claims),
        "message": message,
        "authority": AGENT_AUTHORITY,
        "gate_effect": AGENT_GATE_EFFECT,
        "release_status": AGENT_RELEASE_STATUS,
    }
    return AgentRun(
        schema_version=AGENT_RUN_SCHEMA_VERSION,
        specialist=specialist,
        provider_id=provider_id,
        model_id=model_id,
        objective=objective,
        status=status,
        budget=budget,
        usage=usage,
        steps=steps,
        tool_calls=len(tool_results),
        duration_ms=duration_ms,
        context_sha256=context_sha256,
        tool_result_sha256s=tuple(result.content_sha256 for result in tool_results),
        claims=claims,
        message=message,
        run_sha256=_canonical_sha256(payload),
    )


def _claim_primitive(claim: AgentClaim) -> Mapping[str, Any]:
    return {
        "claim_id": claim.claim_id,
        "title": claim.title,
        "message": claim.message,
        "category": claim.category,
        "severity": claim.severity,
        "confidence": claim.confidence,
        "evidence_ids": claim.evidence_ids,
        "path": claim.path,
        "start_line": claim.start_line,
        "end_line": claim.end_line,
        "assumptions": claim.assumptions,
        "authority": claim.authority,
        "gate_effect": claim.gate_effect,
    }


def _context_sha256(context: Sequence[AgentContextItem]) -> str:
    payload = tuple(
        {
            "evidence_id": item.evidence_id,
            "kind": item.kind,
            "path": item.path,
            "content_sha256": item.content_sha256,
        }
        for item in context
    )
    return _canonical_sha256(payload)


def _usage_budget_exceeded(usage: AgentUsage, budget: AgentBudget) -> str | None:
    if usage.input_tokens > budget.max_input_tokens:
        return "Agent input-token budget exhausted"
    if usage.output_tokens > budget.max_output_tokens:
        return "Agent output-token budget exhausted"
    if usage.cost_microusd > budget.max_cost_microusd:
        return "Agent cost budget exhausted"
    return None


def _bounded_summary(value: str) -> str:
    return _bounded_text(value, "model summary", 2_000)


def _bounded_text(value: str, label: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Agent {label} must be non-empty text")
    text = value.strip()
    if len(text) > max_chars:
        raise ValueError(f"Agent {label} exceeds {max_chars} characters")
    return text


def _clean_identity(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Agent model {label} must be non-empty text")
    return _bounded_text(value, label, 200)


def _canonical_sha256(value: Any) -> str:
    serialized = dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
