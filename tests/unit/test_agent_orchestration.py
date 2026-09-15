from before_deploy.agent_orchestration import (
    AgentReviewOrchestrator,
    exact_claim_sha256,
    resolve_specialists,
)
from before_deploy.agent_runtime import (
    AgentClaimDraft,
    AgentContextItem,
    AgentModelTurn,
)


class FinalModel:
    provider_id = "test-provider"
    model_id = "test-model"

    def __init__(self, claims=(), *, action="FINAL"):
        self.claims = tuple(claims)
        self.action = action

    def complete(self, request):
        return AgentModelTurn(action=self.action, claims=self.claims)


class NoopTools:
    def execute(self, request, *, max_bytes):
        raise AssertionError("these orchestration tests do not request repository tools")


def _context():
    return (
        AgentContextItem.from_text(
            evidence_id="context:auth",
            kind="changed-file",
            path="app/auth.py",
            content="def authorize(user):\n    return True\n",
        ),
    )


def _claim(*, message="Authorization always succeeds", evidence=("context:auth",)):
    return AgentClaimDraft(
        title="Authorization helper allows every user",
        message=message,
        category="security",
        severity="high",
        confidence="high",
        evidence_ids=tuple(evidence),
        path="app/auth.py",
        start_line=1,
        end_line=2,
    )


class Factory:
    def __init__(self, specialist_claims, critic_builder):
        self.specialist_claims = specialist_claims
        self.critic_builder = critic_builder

    def specialist_model(self, specialist):
        return FinalModel(self.specialist_claims.get(specialist.specialist_id, ()))

    def critic_model(self, specialist, candidate):
        return self.critic_builder(specialist, candidate)


def test_multi_specialist_exact_agreement_is_diagnostic_only():
    factory = Factory(
        {
            "general": (_claim(),),
            "security": (_claim(),),
        },
        lambda specialist, candidate: FinalModel((_claim(),)),
    )

    result = AgentReviewOrchestrator().run(
        model_factory=factory,
        tools=NoopTools(),
        context=_context(),
        specialist_ids=("general", "security"),
    )

    assert result.authority == "AI_ORCHESTRATION_ADVISORY"
    assert result.gate_effect == "NONE"
    assert result.release_status == "NOT_EVALUATED"
    assert len(result.corroboration) == 1
    assert result.corroboration[0].status == "MULTI_SPECIALIST_EXACT_CLAIM"
    assert result.corroboration[0].specialist_ids == ("general", "security")
    assert result.corroboration[0].gate_effect == "NONE"
    assert len(result.accepted_claims) == 1
    assert result.critic_assessments[0].decision == "RETAIN"


def test_critic_can_reject_candidate_without_creating_gate_effect():
    factory = Factory(
        {"general": (_claim(),)},
        lambda specialist, candidate: FinalModel(()),
    )

    result = AgentReviewOrchestrator().run(
        model_factory=factory,
        tools=NoopTools(),
        context=_context(),
        specialist_ids=("general",),
    )

    assert result.critic_assessments[0].decision == "REJECT"
    assert result.accepted_claims == ()
    assert result.gate_effect == "NONE"


def test_critic_revision_replaces_candidate_with_evidence_supported_claim():
    revised_message = "Authorization returns True unconditionally for every caller"
    factory = Factory(
        {"general": (_claim(),)},
        lambda specialist, candidate: FinalModel((_claim(message=revised_message),)),
    )

    result = AgentReviewOrchestrator().run(
        model_factory=factory,
        tools=NoopTools(),
        context=_context(),
        specialist_ids=("general",),
    )

    assessment = result.critic_assessments[0]
    assert assessment.decision == "REVISE"
    assert assessment.resulting_claim is not None
    assert result.accepted_claims[0].message == revised_message
    assert exact_claim_sha256(result.accepted_claims[0]) != assessment.candidate_claim_sha256


def test_critic_claim_that_only_cites_candidate_is_rejected():
    class CandidateOnlyFactory(Factory):
        def critic_model(self, specialist, candidate):
            candidate_sha = exact_claim_sha256(candidate)
            return FinalModel(
                (
                    _claim(evidence=(f"critic-candidate:{candidate_sha}",)),
                )
            )

    factory = CandidateOnlyFactory({"general": (_claim(),)}, lambda specialist, candidate: None)

    result = AgentReviewOrchestrator().run(
        model_factory=factory,
        tools=NoopTools(),
        context=_context(),
        specialist_ids=("general",),
    )

    assert result.critic_assessments[0].decision == "REJECT"
    assert result.accepted_claims == ()
    assert "independent" in result.critic_assessments[0].note


def test_failed_critic_is_unreviewed_and_does_not_erase_advisory_candidate():
    factory = Factory(
        {"general": (_claim(),)},
        lambda specialist, candidate: FinalModel((), action="INVALID"),
    )

    result = AgentReviewOrchestrator().run(
        model_factory=factory,
        tools=NoopTools(),
        context=_context(),
        specialist_ids=("general",),
    )

    assert result.critic_assessments[0].decision == "UNREVIEWED"
    assert len(result.accepted_claims) == 1
    assert result.gate_effect == "NONE"


def test_specialist_resolution_rejects_duplicates_and_unknown_ids():
    assert resolve_specialists(("authorization",))[0].domains == ("authorization",)

    try:
        resolve_specialists(("general", "general"))
    except ValueError as error:
        assert "Duplicate" in str(error)
    else:
        raise AssertionError("duplicate specialists must fail")

    try:
        resolve_specialists(("not-a-specialist",))
    except ValueError as error:
        assert "Unknown" in str(error)
    else:
        raise AssertionError("unknown specialists must fail")
