import json

import pytest

from before_deploy.advisory import AdvisoryFinding
from before_deploy.evidence_challenge import (
    EVIDENCE_CHALLENGE_AUTHORITY,
    EVIDENCE_CHALLENGE_GATE_EFFECT,
    OBJECTION_CONTRADICTION,
    OBJECTION_LOCATION,
    OBJECTION_MISSING_SUPPORT,
    VERDICT_CONTRADICTED,
    VERDICT_INSUFFICIENT,
    VERDICT_SUPPORTED,
    ChallengeObjectionDraft,
    EvidenceChallengeDraft,
    normalize_evidence_challenge,
    render_evidence_challenge_json,
    render_evidence_challenge_markdown,
)


def _finding() -> AdvisoryFinding:
    return AdvisoryFinding(
        finding_id="ADV-123",
        source="test-review",
        title="Possible unsafe target",
        message="The request target may reach an unsafe sink.",
        category="security",
        severity="high",
        confidence="medium",
        fingerprint="a" * 64,
    )


def _evidence():
    return {
        "initial:one": "1" * 64,
        "caller:two": "2" * 64,
    }


def test_supported_challenge_is_stable_and_gate_neutral():
    draft = EvidenceChallengeDraft(
        verdict=VERDICT_SUPPORTED,
        summary="The supplied caller evidence supports the reported data flow.",
        evidence_ids=("caller:two", "initial:one"),
    )

    first = normalize_evidence_challenge(
        finding=_finding(), draft=draft, available_evidence=_evidence()
    )
    second = normalize_evidence_challenge(
        finding=_finding(), draft=draft, available_evidence=_evidence()
    )

    assert first == second
    assert first.challenge_id.startswith("ECH-")
    assert first.finding_fingerprint == "a" * 64
    assert first.authority == EVIDENCE_CHALLENGE_AUTHORITY
    assert first.gate_effect == EVIDENCE_CHALLENGE_GATE_EFFECT == "NONE"
    assert [item.evidence_id for item in first.evidence] == ["caller:two", "initial:one"]
    assert first.objections == ()


def test_insufficient_challenge_requires_and_hashes_objection():
    result = normalize_evidence_challenge(
        finding=_finding(),
        draft=EvidenceChallengeDraft(
            verdict=VERDICT_INSUFFICIENT,
            summary="The source is shown, but the sink location is not established.",
            evidence_ids=("initial:one",),
            objections=(
                ChallengeObjectionDraft(
                    kind=OBJECTION_MISSING_SUPPORT,
                    statement="No supplied evidence establishes the claimed sink.",
                    evidence_ids=("initial:one",),
                ),
                ChallengeObjectionDraft(
                    kind=OBJECTION_LOCATION,
                    statement="The reported location is not present in the supplied caller evidence.",
                    evidence_ids=("caller:two",),
                ),
            ),
        ),
        available_evidence=_evidence(),
    )

    assert result.verdict == VERDICT_INSUFFICIENT
    assert len(result.objections) == 2
    assert all(item.objection_id.startswith("OBJ-") for item in result.objections)
    assert {item.evidence_id for item in result.evidence} == {"initial:one", "caller:two"}


def test_contradicted_challenge_cannot_cite_evidence_outside_trace():
    with pytest.raises(ValueError, match="outside the supplied challenge trace"):
        normalize_evidence_challenge(
            finding=_finding(),
            draft=EvidenceChallengeDraft(
                verdict=VERDICT_CONTRADICTED,
                summary="A guard contradicts the unsafe-flow claim.",
                evidence_ids=("caller:two",),
                objections=(
                    ChallengeObjectionDraft(
                        kind=OBJECTION_CONTRADICTION,
                        statement="The caller validates the target before use.",
                        evidence_ids=("hidden:three",),
                    ),
                ),
            ),
            available_evidence=_evidence(),
        )


def test_supported_challenge_rejects_unresolved_objection():
    with pytest.raises(ValueError, match="SUPPORTED challenge cannot contain"):
        normalize_evidence_challenge(
            finding=_finding(),
            draft=EvidenceChallengeDraft(
                verdict=VERDICT_SUPPORTED,
                summary="Supported despite an objection.",
                evidence_ids=("initial:one",),
                objections=(
                    ChallengeObjectionDraft(
                        kind=OBJECTION_MISSING_SUPPORT,
                        statement="This objection remains unresolved.",
                        evidence_ids=("initial:one",),
                    ),
                ),
            ),
            available_evidence=_evidence(),
        )


def test_negative_challenge_requires_an_objection():
    with pytest.raises(ValueError, match="requires at least one objection"):
        normalize_evidence_challenge(
            finding=_finding(),
            draft=EvidenceChallengeDraft(
                verdict=VERDICT_INSUFFICIENT,
                summary="Insufficient without explaining why.",
                evidence_ids=("initial:one",),
            ),
            available_evidence=_evidence(),
        )


def test_challenge_rejects_malformed_content_hash():
    with pytest.raises(ValueError, match="64 lowercase hex"):
        normalize_evidence_challenge(
            finding=_finding(),
            draft=EvidenceChallengeDraft(
                verdict=VERDICT_SUPPORTED,
                summary="Supported.",
                evidence_ids=("initial:one",),
            ),
            available_evidence={"initial:one": "not-a-hash"},
        )


def test_renderers_preserve_advisory_authority_and_content_free_lineage():
    result = normalize_evidence_challenge(
        finding=_finding(),
        draft=EvidenceChallengeDraft(
            verdict=VERDICT_CONTRADICTED,
            summary="The supplied guard contradicts the reported unsafe flow.",
            evidence_ids=("caller:two",),
            objections=(
                ChallengeObjectionDraft(
                    kind=OBJECTION_CONTRADICTION,
                    statement="A caller-side allowlist blocks the unsafe destination.",
                    evidence_ids=("caller:two",),
                ),
            ),
        ),
        available_evidence=_evidence(),
    )

    payload = json.loads(render_evidence_challenge_json(result))["evidence_challenge"]
    assert payload["finding_fingerprint"] == "a" * 64
    assert payload["authority"] == EVIDENCE_CHALLENGE_AUTHORITY
    assert payload["gate_effect"] == "NONE"
    assert payload["evidence"] == [
        {"content_sha256": "2" * 64, "evidence_id": "caller:two"}
    ]

    markdown = render_evidence_challenge_markdown(result)
    assert "Release effect: **none**" in markdown
    assert "AI_EVIDENCE_CHALLENGE_ADVISORY" in markdown
    assert "CONTRADICTED" in markdown
