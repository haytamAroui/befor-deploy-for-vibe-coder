"""Specialist orchestration and critic reflection for native advisory review."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Any, Protocol, Sequence

from before_deploy.agent_runtime import (
    AGENT_GATE_EFFECT,
    AgentClaim,
    AgentContextItem,
    AgentModel,
    AgentRun,
    AgentRuntime,
    AgentToolExecutor,
)

ORCHESTRATION_SCHEMA_VERSION = "before-deploy-agent-orchestration-v1"
ORCHESTRATION_AUTHORITY = "AI_ORCHESTRATION_ADVISORY"
ORCHESTRATION_GATE_EFFECT = AGENT_GATE_EFFECT
CRITIC_DECISIONS = frozenset({"RETAIN", "REVISE", "REJECT", "UNREVIEWED"})


@dataclass(frozen=True)
class SpecialistSpec:
    specialist_id: str
    objective: str
    domains: tuple[str, ...]


SPECIALIST_CATALOG = (
    SpecialistSpec(
        "general",
        "Discover material behavioral defects across the changed code and its bounded dependencies.",
        ("general",),
    ),
    SpecialistSpec(
        "correctness",
        "Investigate correctness, state, error-handling, and data-integrity defects.",
        ("correctness", "data-integrity", "resource-lifetime"),
    ),
    SpecialistSpec(
        "concurrency",
        "Investigate races, ordering, atomicity, locking, cancellation, and concurrent resource lifetime.",
        ("concurrency", "race-conditions"),
    ),
    SpecialistSpec(
        "api-contract",
        "Investigate API contract, compatibility, validation, serialization, and caller/callee mismatches.",
        ("api-contract", "compatibility"),
    ),
    SpecialistSpec(
        "data-flow",
        "Investigate cross-file source-to-sink data flow and unsafe transformations not proven by bounded controls.",
        ("data-flow",),
    ),
    SpecialistSpec(
        "test",
        "Investigate missing or misleading tests, untested failure paths, and regression coverage gaps.",
        ("test",),
    ),
    SpecialistSpec(
        "security",
        "Investigate security weaknesses outside the proven coverage of deterministic controls.",
        ("security",),
    ),
    SpecialistSpec("authorization", "Investigate authorization and object/action access-control failures.", ("authorization",)),
    SpecialistSpec("authentication", "Investigate authentication, identity, and credential-validation failures.", ("authentication",)),
    SpecialistSpec("injection", "Investigate injection and unsafe interpreter/query/shell boundaries.", ("injection",)),
    SpecialistSpec("ssrf", "Investigate server-side request forgery and unsafe outbound target control.", ("ssrf",)),
    SpecialistSpec("secrets", "Investigate secret exposure, credential handling, and accidental disclosure.", ("secrets",)),
    SpecialistSpec("cryptography", "Investigate cryptographic misuse, key handling, randomness, and verification failures.", ("cryptography",)),
    SpecialistSpec("session", "Investigate session lifecycle, cookie, fixation, revocation, and state-binding failures.", ("session",)),
    SpecialistSpec("deserialization", "Investigate unsafe deserialization and untrusted object reconstruction.", ("deserialization",)),
    SpecialistSpec("file-upload", "Investigate upload validation, storage, execution, and content-handling failures.", ("file-upload",)),
    SpecialistSpec("path-traversal", "Investigate unsafe path composition, traversal, and filesystem boundary failures.", ("path-traversal",)),
    SpecialistSpec("business-logic", "Investigate business-rule bypasses, invariant violations, and workflow abuse.", ("business-logic",)),
    SpecialistSpec("supply-chain", "Investigate dependency, build, provenance, and supply-chain risks.", ("supply-chain",)),
    SpecialistSpec("cloud-iac", "Investigate cloud and infrastructure-as-code exposure or privilege risks.", ("cloud-iac",)),
)

DEFAULT_SPECIALIST_IDS = (
    "general",
    "correctness",
    "concurrency",
    "api-contract",
    "data-flow",
    "test",
    "security",
)


@dataclass(frozen=True)
class ClaimCorroboration:
    claim_sha256: str
    representative_claim_id: str
    occurrence_count: int
    specialist_ids: tuple[str, ...]
    provider_ids: tuple[str, ...]
    model_ids: tuple[str, ...]
    run_sha256s: tuple[str, ...]
    status: str
    authority: str = ORCHESTRATION_AUTHORITY
    gate_effect: str = ORCHESTRATION_GATE_EFFECT


@dataclass(frozen=True)
class CriticAssessment:
    candidate_claim_sha256: str
    candidate_claim_id: str
    decision: str
    critic_run_sha256: str | None
    resulting_claim: AgentClaim | None
    note: str
    authority: str = ORCHESTRATION_AUTHORITY
    gate_effect: str = ORCHESTRATION_GATE_EFFECT


@dataclass(frozen=True)
class AgentReviewResult:
    schema_version: str
    specialist_runs: tuple[AgentRun, ...]
    corroboration: tuple[ClaimCorroboration, ...]
    critic_assessments: tuple[CriticAssessment, ...]
    accepted_claims: tuple[AgentClaim, ...]
    orchestration_sha256: str
    authority: str = ORCHESTRATION_AUTHORITY
    gate_effect: str = ORCHESTRATION_GATE_EFFECT
    release_status: str = "NOT_EVALUATED"


class AgentModelFactory(Protocol):
    """Resolve independent specialist and critic model adapters."""

    def specialist_model(self, specialist: SpecialistSpec) -> AgentModel: ...

    def critic_model(self, specialist: SpecialistSpec, candidate: AgentClaim) -> AgentModel: ...


class AgentReviewOrchestrator:
    """Run independent specialists, exact-claim corroboration, then one critic per claim."""

    def __init__(self, *, runtime: AgentRuntime | None = None) -> None:
        self.runtime = runtime or AgentRuntime()

    def run(
        self,
        *,
        model_factory: AgentModelFactory,
        tools: AgentToolExecutor,
        context: Sequence[AgentContextItem],
        specialist_ids: Sequence[str] = DEFAULT_SPECIALIST_IDS,
    ) -> AgentReviewResult:
        specialists = resolve_specialists(specialist_ids)
        specialist_runs = tuple(
            self.runtime.run(
                model=model_factory.specialist_model(spec),
                tools=tools,
                specialist=spec.specialist_id,
                objective=spec.objective,
                context=context,
            )
            for spec in specialists
        )
        grouped = _group_claims(specialist_runs)
        corroboration = tuple(
            _corroboration_for(claim_sha256, occurrences)
            for claim_sha256, occurrences in sorted(grouped.items())
        )

        assessments: list[CriticAssessment] = []
        accepted: dict[str, AgentClaim] = {}
        for claim_sha256, occurrences in sorted(grouped.items()):
            candidate_run, candidate = occurrences[0]
            specialist = _specialist_by_id(candidate_run.specialist)
            assessment = self._critic_assessment(
                model_factory=model_factory,
                tools=tools,
                context=context,
                specialist=specialist,
                candidate=candidate,
                candidate_claim_sha256=claim_sha256,
            )
            assessments.append(assessment)
            if assessment.decision == "REJECT":
                continue
            retained = assessment.resulting_claim or candidate
            accepted[exact_claim_sha256(retained)] = retained

        accepted_claims = tuple(accepted[key] for key in sorted(accepted))
        result_payload = {
            "schema_version": ORCHESTRATION_SCHEMA_VERSION,
            "specialist_run_sha256s": tuple(run.run_sha256 for run in specialist_runs),
            "corroboration": tuple(_corroboration_primitive(item) for item in corroboration),
            "critic_assessments": tuple(_assessment_primitive(item) for item in assessments),
            "accepted_claims": tuple(_claim_primitive(item) for item in accepted_claims),
            "authority": ORCHESTRATION_AUTHORITY,
            "gate_effect": ORCHESTRATION_GATE_EFFECT,
            "release_status": "NOT_EVALUATED",
        }
        return AgentReviewResult(
            schema_version=ORCHESTRATION_SCHEMA_VERSION,
            specialist_runs=specialist_runs,
            corroboration=corroboration,
            critic_assessments=tuple(assessments),
            accepted_claims=accepted_claims,
            orchestration_sha256=_canonical_sha256(result_payload),
        )

    def _critic_assessment(
        self,
        *,
        model_factory: AgentModelFactory,
        tools: AgentToolExecutor,
        context: Sequence[AgentContextItem],
        specialist: SpecialistSpec,
        candidate: AgentClaim,
        candidate_claim_sha256: str,
    ) -> CriticAssessment:
        candidate_evidence_id = f"critic-candidate:{candidate_claim_sha256}"
        candidate_context = AgentContextItem.from_text(
            evidence_id=candidate_evidence_id,
            kind="critic-candidate",
            path=candidate.path,
            content=dumps(
                _claim_primitive(candidate),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ),
        )
        critic_run = self.runtime.run(
            model=model_factory.critic_model(specialist, candidate),
            tools=tools,
            specialist="critic",
            objective=(
                "Challenge the candidate finding. Seek counter-evidence, reachability or sanitizer context, "
                "and retain or revise only claims supported by evidence beyond the candidate itself."
            ),
            context=tuple(context) + (candidate_context,),
        )
        if critic_run.status != "COMPLETED":
            return CriticAssessment(
                candidate_claim_sha256=candidate_claim_sha256,
                candidate_claim_id=candidate.claim_id,
                decision="UNREVIEWED",
                critic_run_sha256=critic_run.run_sha256,
                resulting_claim=None,
                note=f"Critic did not complete: {critic_run.status}",
            )
        if not critic_run.claims:
            return CriticAssessment(
                candidate_claim_sha256=candidate_claim_sha256,
                candidate_claim_id=candidate.claim_id,
                decision="REJECT",
                critic_run_sha256=critic_run.run_sha256,
                resulting_claim=None,
                note="Critic completed without retaining a supported claim.",
            )
        if len(critic_run.claims) != 1:
            return CriticAssessment(
                candidate_claim_sha256=candidate_claim_sha256,
                candidate_claim_id=candidate.claim_id,
                decision="UNREVIEWED",
                critic_run_sha256=critic_run.run_sha256,
                resulting_claim=None,
                note="Critic returned an ambiguous number of candidate assessments.",
            )

        result = critic_run.claims[0]
        independent_evidence = set(result.evidence_ids) - {candidate_evidence_id}
        if not independent_evidence:
            return CriticAssessment(
                candidate_claim_sha256=candidate_claim_sha256,
                candidate_claim_id=candidate.claim_id,
                decision="REJECT",
                critic_run_sha256=critic_run.run_sha256,
                resulting_claim=None,
                note="Critic claim cited only the candidate and no independent bounded evidence.",
            )
        decision = "RETAIN" if exact_claim_sha256(result) == candidate_claim_sha256 else "REVISE"
        return CriticAssessment(
            candidate_claim_sha256=candidate_claim_sha256,
            candidate_claim_id=candidate.claim_id,
            decision=decision,
            critic_run_sha256=critic_run.run_sha256,
            resulting_claim=result,
            note="Critic retained an evidence-supported claim." if decision == "RETAIN" else "Critic revised the claim against bounded evidence.",
        )


def resolve_specialists(specialist_ids: Sequence[str]) -> tuple[SpecialistSpec, ...]:
    if not specialist_ids:
        raise ValueError("At least one agent specialist is required")
    catalog = {item.specialist_id: item for item in SPECIALIST_CATALOG}
    resolved = []
    seen = set()
    for specialist_id in specialist_ids:
        if specialist_id in seen:
            raise ValueError(f"Duplicate agent specialist: {specialist_id}")
        try:
            resolved.append(catalog[specialist_id])
        except KeyError as error:
            raise ValueError(f"Unknown agent specialist: {specialist_id}") from error
        seen.add(specialist_id)
    return tuple(resolved)


def exact_claim_sha256(claim: AgentClaim) -> str:
    """Hash exact normalized claim semantics, intentionally excluding provenance/confidence."""
    payload = {
        "title": claim.title,
        "message": claim.message,
        "category": claim.category,
        "severity": claim.severity,
        "path": claim.path,
        "start_line": claim.start_line,
        "end_line": claim.end_line,
        "assumptions": tuple(sorted(claim.assumptions)),
    }
    return _canonical_sha256(payload)


def _group_claims(
    runs: Sequence[AgentRun],
) -> dict[str, list[tuple[AgentRun, AgentClaim]]]:
    grouped: dict[str, list[tuple[AgentRun, AgentClaim]]] = {}
    for run in runs:
        if run.status != "COMPLETED":
            continue
        for claim in run.claims:
            grouped.setdefault(exact_claim_sha256(claim), []).append((run, claim))
    for occurrences in grouped.values():
        occurrences.sort(key=lambda item: (item[0].specialist, item[0].run_sha256, item[1].claim_id))
    return grouped


def _corroboration_for(
    claim_sha256: str,
    occurrences: Sequence[tuple[AgentRun, AgentClaim]],
) -> ClaimCorroboration:
    specialists = tuple(sorted({run.specialist for run, _ in occurrences}))
    providers = tuple(sorted({run.provider_id for run, _ in occurrences}))
    models = tuple(sorted({run.model_id for run, _ in occurrences}))
    run_sha256s = tuple(sorted({run.run_sha256 for run, _ in occurrences}))
    if len(specialists) >= 2:
        status = "MULTI_SPECIALIST_EXACT_CLAIM"
    elif len(run_sha256s) >= 2:
        status = "MULTI_EXECUTION_EXACT_CLAIM"
    elif len(occurrences) >= 2:
        status = "REPEATED_EXACT_CLAIM"
    else:
        status = "SINGLE"
    return ClaimCorroboration(
        claim_sha256=claim_sha256,
        representative_claim_id=occurrences[0][1].claim_id,
        occurrence_count=len(occurrences),
        specialist_ids=specialists,
        provider_ids=providers,
        model_ids=models,
        run_sha256s=run_sha256s,
        status=status,
    )


def _specialist_by_id(specialist_id: str) -> SpecialistSpec:
    for specialist in SPECIALIST_CATALOG:
        if specialist.specialist_id == specialist_id:
            return specialist
    raise ValueError(f"Unknown specialist in completed run: {specialist_id}")


def _claim_primitive(claim: AgentClaim) -> dict[str, Any]:
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


def _corroboration_primitive(value: ClaimCorroboration) -> dict[str, Any]:
    return {
        "claim_sha256": value.claim_sha256,
        "representative_claim_id": value.representative_claim_id,
        "occurrence_count": value.occurrence_count,
        "specialist_ids": value.specialist_ids,
        "provider_ids": value.provider_ids,
        "model_ids": value.model_ids,
        "run_sha256s": value.run_sha256s,
        "status": value.status,
        "authority": value.authority,
        "gate_effect": value.gate_effect,
    }


def _assessment_primitive(value: CriticAssessment) -> dict[str, Any]:
    return {
        "candidate_claim_sha256": value.candidate_claim_sha256,
        "candidate_claim_id": value.candidate_claim_id,
        "decision": value.decision,
        "critic_run_sha256": value.critic_run_sha256,
        "resulting_claim": None if value.resulting_claim is None else _claim_primitive(value.resulting_claim),
        "note": value.note,
        "authority": value.authority,
        "gate_effect": value.gate_effect,
    }


def _canonical_sha256(value: Any) -> str:
    serialized = dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
