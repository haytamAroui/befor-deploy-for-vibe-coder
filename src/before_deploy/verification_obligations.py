"""AI-proposed, explicitly human-frozen verification obligations and deterministic results."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Mapping, Sequence

VERIFICATION_OBLIGATION_SCHEMA = "before-deploy-verification-obligation-v1"
VERIFICATION_RESULT_SCHEMA = "before-deploy-verification-result-v1"
VERIFICATION_AUTHORITY = "HUMAN_FROZEN_VERIFICATION_PLAN"
VERIFICATION_GATE_EFFECT = "NONE"

KIND_TEST = "TEST"
KIND_STATIC_CHECK = "STATIC_CHECK"
KIND_REPRODUCTION = "REPRODUCTION"
KIND_MANUAL_REVIEW = "MANUAL_REVIEW"
_ALLOWED_KINDS = {KIND_TEST, KIND_STATIC_CHECK, KIND_REPRODUCTION, KIND_MANUAL_REVIEW}

RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_ERROR = "ERROR"
_ALLOWED_RESULTS = {RESULT_PASS, RESULT_FAIL, RESULT_ERROR}


@dataclass(frozen=True)
class VerificationObligationDraft:
    """AI-authored proposal. It has no execution or release authority."""

    target_fingerprint: str
    title: str
    rationale: str
    kind: str
    success_criterion: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationObligationProposal:
    proposal_id: str
    target_fingerprint: str
    title: str
    rationale: str
    kind: str
    success_criterion: str
    evidence_ids: tuple[str, ...]
    authority: str = "AI_VERIFICATION_PROPOSAL_ADVISORY"
    gate_effect: str = VERIFICATION_GATE_EFFECT


@dataclass(frozen=True)
class FrozenVerificationObligation:
    """Immutable obligation after explicit human approval."""

    obligation_id: str
    proposal_id: str
    target_fingerprint: str
    title: str
    rationale: str
    kind: str
    success_criterion: str
    evidence_ids: tuple[str, ...]
    frozen_by: str
    approval_reference: str
    schema_version: str = VERIFICATION_OBLIGATION_SCHEMA
    authority: str = VERIFICATION_AUTHORITY
    gate_effect: str = VERIFICATION_GATE_EFFECT


@dataclass(frozen=True)
class VerificationResult:
    result_id: str
    obligation_id: str
    status: str
    summary: str
    executor: str
    evidence: tuple[tuple[str, str], ...]
    schema_version: str = VERIFICATION_RESULT_SCHEMA
    authority: str = "DETERMINISTIC_VERIFICATION_EVIDENCE"
    gate_effect: str = VERIFICATION_GATE_EFFECT


def propose_verification_obligation(
    draft: VerificationObligationDraft,
    *,
    available_evidence_ids: Sequence[str] = (),
) -> VerificationObligationProposal:
    """Normalize an AI-authored proposal without granting execution authority."""
    target = _fingerprint(draft.target_fingerprint)
    title = _text(draft.title, "verification title", 500)
    rationale = _text(draft.rationale, "verification rationale", 8_000)
    kind = _enum(draft.kind, _ALLOWED_KINDS, "verification kind")
    criterion = _text(draft.success_criterion, "verification success criterion", 8_000)
    available = {_text(item, "available evidence id", 500) for item in available_evidence_ids}
    evidence_ids = tuple(sorted({_text(item, "verification evidence id", 500) for item in draft.evidence_ids}))
    if set(evidence_ids) - available:
        raise ValueError("Verification proposal cites evidence outside the supplied trace")
    payload = {
        "target_fingerprint": target,
        "title": title,
        "rationale": rationale,
        "kind": kind,
        "success_criterion": criterion,
        "evidence_ids": list(evidence_ids),
    }
    return VerificationObligationProposal(
        proposal_id=f"VOP-{_digest(payload)[:16]}",
        target_fingerprint=target,
        title=title,
        rationale=rationale,
        kind=kind,
        success_criterion=criterion,
        evidence_ids=evidence_ids,
    )


def freeze_verification_obligation(
    proposal: VerificationObligationProposal,
    *,
    frozen_by: str,
    approval_reference: str,
) -> FrozenVerificationObligation:
    """Freeze a proposal at the explicit human-approval boundary."""
    if proposal.gate_effect != VERIFICATION_GATE_EFFECT:
        raise ValueError("Verification proposal must remain gate-neutral before freeze")
    actor = _text(frozen_by, "frozen_by", 500)
    approval = _text(approval_reference, "approval_reference", 1_000)
    payload = {
        "proposal_id": proposal.proposal_id,
        "target_fingerprint": proposal.target_fingerprint,
        "title": proposal.title,
        "rationale": proposal.rationale,
        "kind": proposal.kind,
        "success_criterion": proposal.success_criterion,
        "evidence_ids": list(proposal.evidence_ids),
        "frozen_by": actor,
        "approval_reference": approval,
    }
    return FrozenVerificationObligation(
        obligation_id=f"VOB-{_digest(payload)[:16]}",
        proposal_id=proposal.proposal_id,
        target_fingerprint=proposal.target_fingerprint,
        title=proposal.title,
        rationale=proposal.rationale,
        kind=proposal.kind,
        success_criterion=proposal.success_criterion,
        evidence_ids=proposal.evidence_ids,
        frozen_by=actor,
        approval_reference=approval,
    )


def record_verification_result(
    obligation: FrozenVerificationObligation,
    *,
    status: str,
    summary: str,
    executor: str,
    evidence: Mapping[str, str],
) -> VerificationResult:
    """Attach a deterministic external execution result to a frozen obligation."""
    if obligation.authority != VERIFICATION_AUTHORITY:
        raise ValueError("Verification result requires a human-frozen obligation")
    normalized_status = _enum(status, _ALLOWED_RESULTS, "verification result")
    normalized_summary = _text(summary, "verification result summary", 8_000)
    normalized_executor = _text(executor, "verification executor", 500)
    normalized_evidence = _evidence_hashes(evidence)
    if not normalized_evidence:
        raise ValueError("Verification result requires hashed result evidence")
    payload = {
        "obligation_id": obligation.obligation_id,
        "status": normalized_status,
        "summary": normalized_summary,
        "executor": normalized_executor,
        "evidence": [list(item) for item in normalized_evidence],
    }
    return VerificationResult(
        result_id=f"VR-{_digest(payload)[:16]}",
        obligation_id=obligation.obligation_id,
        status=normalized_status,
        summary=normalized_summary,
        executor=normalized_executor,
        evidence=normalized_evidence,
    )


def render_frozen_obligation_json(result: FrozenVerificationObligation) -> str:
    payload = {
        "schema_version": result.schema_version,
        "verification_obligation": {
            "obligation_id": result.obligation_id,
            "proposal_id": result.proposal_id,
            "target_fingerprint": result.target_fingerprint,
            "title": result.title,
            "rationale": result.rationale,
            "kind": result.kind,
            "success_criterion": result.success_criterion,
            "evidence_ids": list(result.evidence_ids),
            "frozen_by": result.frozen_by,
            "approval_reference": result.approval_reference,
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_verification_result_json(result: VerificationResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "verification_result": {
            "result_id": result.result_id,
            "obligation_id": result.obligation_id,
            "status": result.status,
            "summary": result.summary,
            "executor": result.executor,
            "evidence": [
                {"evidence_id": evidence_id, "content_sha256": digest}
                for evidence_id, digest in result.evidence
            ],
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _evidence_hashes(value: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise ValueError("Verification result evidence must be a mapping")
    result = []
    for raw_id, raw_hash in value.items():
        evidence_id = _text(raw_id, "verification result evidence id", 500)
        digest = _sha256_text(raw_hash)
        result.append((evidence_id, digest))
    return tuple(sorted(result))


def _fingerprint(value: str) -> str:
    text = _text(value, "target fingerprint", 256).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("Verification target fingerprint must be a 64-character SHA-256 hex value")
    return text


def _sha256_text(value: str) -> str:
    text = _text(value, "content sha256", 64).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("Verification result content_sha256 must be 64 lowercase hex characters")
    return text


def _enum(value: str, allowed: set[str], label: str) -> str:
    text = _text(value, label, 100).upper()
    if text not in allowed:
        raise ValueError(f"Unsupported {label}: {text}")
    return text


def _text(value: str, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    text = value.strip()
    if len(text) > limit:
        raise ValueError(f"{label} exceeds maximum length")
    return text


def _digest(payload: object) -> str:
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()
