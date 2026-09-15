import json

import pytest

from before_deploy.advisory import AdvisoryFinding
from before_deploy.assurance_case import (
    ASSURANCE_CASE_AUTHORITY,
    ASSURANCE_CASE_GATE_EFFECT,
    ORIGIN_EXPANDED,
    ORIGIN_INITIAL,
    POSTURE_CHALLENGE_SUPPORTED,
    POSTURE_CLAIM_CONTRADICTED,
    POSTURE_UNCHALLENGED,
    AssuranceEvidence,
    InvestigationStepDraft,
    build_assurance_case,
    render_assurance_case_json,
    render_assurance_case_markdown,
)
from before_deploy.evidence_challenge import (
    OBJECTION_CONTRADICTION,
    VERDICT_CONTRADICTED,
    VERDICT_SUPPORTED,
    ChallengeObjectionDraft,
    EvidenceChallengeDraft,
    normalize_evidence_challenge,
)


def _finding(fingerprint="a" * 64):
    return AdvisoryFinding(
        finding_id="ADV-graph",
        source="test-review",
        title="Possible unsafe flow",
        message="A caller may use data unsafely.",
        category="security",
        severity="high",
        confidence="medium",
        fingerprint=fingerprint,
    )


def _evidence():
    return (
        AssuranceEvidence("initial:one", "1" * 64, ORIGIN_INITIAL),
        AssuranceEvidence("caller:two", "2" * 64, ORIGIN_EXPANDED, "find_callers"),
    )


def _supported_challenge():
    return normalize_evidence_challenge(
        finding=_finding(),
        draft=EvidenceChallengeDraft(
            verdict=VERDICT_SUPPORTED,
            summary="The supplied caller evidence supports the finding.",
            evidence_ids=("initial:one", "caller:two"),
        ),
        available_evidence={"initial:one": "1" * 64, "caller:two": "2" * 64},
    )


def _contradicted_challenge():
    return normalize_evidence_challenge(
        finding=_finding(),
        draft=EvidenceChallengeDraft(
            verdict=VERDICT_CONTRADICTED,
            summary="The caller guard contradicts the finding.",
            evidence_ids=("caller:two",),
            objections=(
                ChallengeObjectionDraft(
                    kind=OBJECTION_CONTRADICTION,
                    statement="The caller enforces an allowlist before the sink.",
                    evidence_ids=("caller:two",),
                ),
            ),
        ),
        available_evidence={"initial:one": "1" * 64, "caller:two": "2" * 64},
    )


def test_assurance_case_is_stable_and_captures_investigation_and_challenge_graph():
    step = InvestigationStepDraft(
        action="find_callers(target_url)",
        input_evidence_ids=("initial:one",),
        output_evidence_ids=("caller:two",),
    )
    first = build_assurance_case(
        finding=_finding(),
        evidence=_evidence(),
        investigation_steps=(step,),
        challenge=_supported_challenge(),
    )
    second = build_assurance_case(
        finding=_finding(),
        evidence=tuple(reversed(_evidence())),
        investigation_steps=(step,),
        challenge=_supported_challenge(),
    )

    assert first == second
    assert first.case_id.startswith("AC-")
    assert first.posture == POSTURE_CHALLENGE_SUPPORTED
    assert first.authority == ASSURANCE_CASE_AUTHORITY
    assert first.gate_effect == ASSURANCE_CASE_GATE_EFFECT == "NONE"
    assert len(first.investigation_steps) == 1
    assert {node.kind for node in first.nodes} == {
        "FINDING",
        "EVIDENCE",
        "INVESTIGATION",
        "CHALLENGE",
    }
    assert {edge.relation for edge in first.edges} >= {
        "HAS_EVIDENCE",
        "READS",
        "PRODUCES",
        "CHALLENGES",
        "CITES",
    }


def test_assurance_case_maps_contradicted_challenge_to_diagnostic_posture():
    result = build_assurance_case(
        finding=_finding(),
        evidence=_evidence(),
        challenge=_contradicted_challenge(),
    )

    assert result.posture == POSTURE_CLAIM_CONTRADICTED
    assert "OBJECTION" in {node.kind for node in result.nodes}
    assert "PART_OF" in {edge.relation for edge in result.edges}
    assert result.gate_effect == "NONE"


def test_assurance_case_without_challenge_is_explicitly_unchallenged():
    result = build_assurance_case(finding=_finding(), evidence=_evidence())
    assert result.posture == POSTURE_UNCHALLENGED
    assert result.challenge_id is None
    assert result.challenge_verdict is None


def test_assurance_case_rejects_investigation_evidence_outside_graph():
    with pytest.raises(ValueError, match="outside the graph"):
        build_assurance_case(
            finding=_finding(),
            evidence=_evidence(),
            investigation_steps=(
                InvestigationStepDraft(
                    action="find_callers(target_url)",
                    input_evidence_ids=("initial:one",),
                    output_evidence_ids=("hidden:three",),
                ),
            ),
        )


def test_assurance_case_rejects_challenge_for_another_finding():
    challenge = _supported_challenge()
    with pytest.raises(ValueError, match="targets another finding"):
        build_assurance_case(
            finding=_finding("b" * 64),
            evidence=_evidence(),
            challenge=challenge,
        )


def test_assurance_case_rejects_challenge_evidence_hash_drift():
    challenge = _supported_challenge()
    with pytest.raises(ValueError, match="hash mismatch"):
        build_assurance_case(
            finding=_finding(),
            evidence=(
                AssuranceEvidence("initial:one", "1" * 64, ORIGIN_INITIAL),
                AssuranceEvidence("caller:two", "3" * 64, ORIGIN_EXPANDED),
            ),
            challenge=challenge,
        )


def test_assurance_case_renderers_keep_release_authority_outside_graph():
    result = build_assurance_case(
        finding=_finding(),
        evidence=_evidence(),
        challenge=_supported_challenge(),
    )
    payload = json.loads(render_assurance_case_json(result))["assurance_case"]

    assert payload["authority"] == ASSURANCE_CASE_AUTHORITY
    assert payload["gate_effect"] == "NONE"
    assert payload["posture"] == POSTURE_CHALLENGE_SUPPORTED
    assert all("content" not in node for node in payload["nodes"])

    markdown = render_assurance_case_markdown(result)
    assert "Release authority: **none**" in markdown
    assert "CHALLENGE_SUPPORTED" in markdown
