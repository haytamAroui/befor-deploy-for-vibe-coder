"""Bounded, gate-neutral semantic challenge records for advisory findings."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from typing import Mapping, Sequence

from before_deploy.advisory import ADVISORY_GATE_EFFECT, AdvisoryFinding

EVIDENCE_CHALLENGE_SCHEMA = "before-deploy-evidence-challenge-v1"
EVIDENCE_CHALLENGE_AUTHORITY = "AI_EVIDENCE_CHALLENGE_ADVISORY"
EVIDENCE_CHALLENGE_GATE_EFFECT = "NONE"

VERDICT_SUPPORTED = "SUPPORTED"
VERDICT_INSUFFICIENT = "INSUFFICIENT"
VERDICT_CONTRADICTED = "CONTRADICTED"
VERDICT_UNRESOLVED = "UNRESOLVED"
_ALLOWED_VERDICTS = {
    VERDICT_SUPPORTED,
    VERDICT_INSUFFICIENT,
    VERDICT_CONTRADICTED,
    VERDICT_UNRESOLVED,
}

OBJECTION_MISSING_SUPPORT = "MISSING_SUPPORT"
OBJECTION_CONTRADICTION = "CONTRADICTION"
OBJECTION_SCOPE = "SCOPE"
OBJECTION_LOCATION = "LOCATION"
OBJECTION_OTHER = "OTHER"
_ALLOWED_OBJECTION_KINDS = {
    OBJECTION_MISSING_SUPPORT,
    OBJECTION_CONTRADICTION,
    OBJECTION_SCOPE,
    OBJECTION_LOCATION,
    OBJECTION_OTHER,
}


@dataclass(frozen=True)
class ChallengeEvidence:
    """Content-free identity for evidence supplied to the challenger."""

    evidence_id: str
    content_sha256: str


@dataclass(frozen=True)
class ChallengeObjectionDraft:
    """Model-authored objection before deterministic normalization."""

    kind: str
    statement: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceChallengeDraft:
    """Model-authored semantic assessment over one advisory finding."""

    verdict: str
    summary: str
    evidence_ids: tuple[str, ...]
    objections: tuple[ChallengeObjectionDraft, ...] = ()


@dataclass(frozen=True)
class ChallengeObjection:
    objection_id: str
    kind: str
    statement: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceChallengeAssessment:
    """Normalized challenge result. It cannot alter release or finding authority."""

    challenge_id: str
    finding_id: str
    finding_fingerprint: str
    verdict: str
    summary: str
    evidence: tuple[ChallengeEvidence, ...]
    objections: tuple[ChallengeObjection, ...]
    schema_version: str = EVIDENCE_CHALLENGE_SCHEMA
    authority: str = EVIDENCE_CHALLENGE_AUTHORITY
    gate_effect: str = EVIDENCE_CHALLENGE_GATE_EFFECT


def normalize_evidence_challenge(
    *,
    finding: AdvisoryFinding,
    draft: EvidenceChallengeDraft,
    available_evidence: Mapping[str, str],
) -> EvidenceChallengeAssessment:
    """Validate and hash a semantic challenge without changing the finding."""
    if finding.gate_effect != ADVISORY_GATE_EFFECT:
        raise ValueError("Evidence Challenge accepts gate-neutral advisory findings only")
    if not finding.fingerprint.strip() or not finding.finding_id.strip():
        raise ValueError("Evidence Challenge finding identity must be non-empty")

    evidence_hashes = _available_evidence(available_evidence)
    verdict = _enum(draft.verdict, _ALLOWED_VERDICTS, "challenge verdict")
    summary = _text(draft.summary, "challenge summary", 8_000)
    cited_ids = _evidence_ids(draft.evidence_ids, evidence_hashes, "challenge")
    objections = tuple(
        _normalize_objection(item, evidence_hashes=evidence_hashes) for item in draft.objections
    )

    if verdict in {VERDICT_INSUFFICIENT, VERDICT_CONTRADICTED} and not objections:
        raise ValueError(f"{verdict} challenge requires at least one objection")
    if verdict == VERDICT_SUPPORTED and objections:
        raise ValueError("SUPPORTED challenge cannot contain unresolved objections")

    all_ids = set(cited_ids)
    for objection in objections:
        all_ids.update(objection.evidence_ids)
    if not all_ids:
        raise ValueError("Evidence Challenge must cite supplied evidence")

    evidence = tuple(
        ChallengeEvidence(evidence_id=evidence_id, content_sha256=evidence_hashes[evidence_id])
        for evidence_id in sorted(all_ids)
    )
    challenge_payload = {
        "finding_fingerprint": finding.fingerprint,
        "verdict": verdict,
        "summary": summary,
        "evidence": [
            {"evidence_id": item.evidence_id, "content_sha256": item.content_sha256}
            for item in evidence
        ],
        "objections": [
            {
                "objection_id": item.objection_id,
                "kind": item.kind,
                "statement": item.statement,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in objections
        ],
    }
    challenge_id = f"ECH-{_digest(challenge_payload)[:16]}"
    return EvidenceChallengeAssessment(
        challenge_id=challenge_id,
        finding_id=finding.finding_id,
        finding_fingerprint=finding.fingerprint,
        verdict=verdict,
        summary=summary,
        evidence=evidence,
        objections=objections,
    )


def render_evidence_challenge_json(result: EvidenceChallengeAssessment) -> str:
    payload = {
        "schema_version": result.schema_version,
        "evidence_challenge": {
            "challenge_id": result.challenge_id,
            "finding_id": result.finding_id,
            "finding_fingerprint": result.finding_fingerprint,
            "verdict": result.verdict,
            "summary": result.summary,
            "evidence": [
                {"evidence_id": item.evidence_id, "content_sha256": item.content_sha256}
                for item in result.evidence
            ],
            "objections": [
                {
                    "objection_id": item.objection_id,
                    "kind": item.kind,
                    "statement": item.statement,
                    "evidence_ids": list(item.evidence_ids),
                }
                for item in result.objections
            ],
            "authority": result.authority,
            "gate_effect": result.gate_effect,
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_evidence_challenge_markdown(result: EvidenceChallengeAssessment) -> str:
    lines = [
        "# Evidence Challenge",
        "",
        f"- Challenge: `{result.challenge_id}`",
        f"- Finding: `{result.finding_id}` / `{result.finding_fingerprint}`",
        f"- Verdict: **{result.verdict}**",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        "- Release effect: **none**; this semantic assessment does not alter deterministic authority.",
        "",
        result.summary,
        "",
        "## Evidence",
        "",
    ]
    lines.extend(
        f"- `{item.evidence_id}` (`sha256:{item.content_sha256}`)" for item in result.evidence
    )
    lines.extend(["", "## Objections", ""])
    if result.objections:
        lines.extend(
            f"- `{item.objection_id}` `{item.kind}` — {item.statement}"
            for item in result.objections
        )
    else:
        lines.append("- No unresolved objection was recorded.")
    return "\n".join(lines) + "\n"


def _normalize_objection(
    draft: ChallengeObjectionDraft,
    *,
    evidence_hashes: Mapping[str, str],
) -> ChallengeObjection:
    kind = _enum(draft.kind, _ALLOWED_OBJECTION_KINDS, "objection kind")
    statement = _text(draft.statement, "objection statement", 8_000)
    evidence_ids = _evidence_ids(draft.evidence_ids, evidence_hashes, "objection")
    payload = {
        "kind": kind,
        "statement": statement,
        "evidence_ids": list(evidence_ids),
    }
    return ChallengeObjection(
        objection_id=f"OBJ-{_digest(payload)[:16]}",
        kind=kind,
        statement=statement,
        evidence_ids=evidence_ids,
    )


def _available_evidence(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("Evidence Challenge requires available evidence")
    result: dict[str, str] = {}
    for raw_id, raw_hash in value.items():
        evidence_id = _text(raw_id, "evidence id", 500)
        digest = _sha256_text(raw_hash)
        if evidence_id in result:
            raise ValueError("Duplicate Evidence Challenge evidence id")
        result[evidence_id] = digest
    return result


def _evidence_ids(
    values: Sequence[str],
    available: Mapping[str, str],
    label: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{label} evidence_ids must be a sequence")
    result = tuple(sorted({_text(item, f"{label} evidence id", 500) for item in values}))
    unknown = set(result) - set(available)
    if unknown:
        raise ValueError(f"{label} cites evidence outside the supplied challenge trace")
    return result


def _sha256_text(value: str) -> str:
    text = _text(value, "evidence sha256", 64).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("Evidence Challenge content_sha256 must be 64 lowercase hex characters")
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
