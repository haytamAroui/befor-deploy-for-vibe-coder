import json
from pathlib import Path

from before_deploy.caller_experiment import (
    CallerClaimDraft,
    CallerExperiment,
    CallerTurn,
    InitialEvidence,
    advisory_import_from_caller_run,
    comparative_finding_evidence,
)


class ScriptedModel:
    provider_id = "fixture-provider"
    model_id = "fixture-model"

    def __init__(self, turns):
        self.turns = list(turns)
        self.inputs = []

    def complete(self, request):
        self.inputs.append(request)
        turn = self.turns.pop(0)
        if callable(turn):
            return turn(request)
        return turn


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "app" / "policy.py").write_text(
        "def authorize(user, resource):\n"
        "    return user.tenant_id == resource.tenant_id\n",
        encoding="utf-8",
    )
    (root / "app" / "api.py").write_text(
        "from app.policy import authorize\n\n"
        "def delete_resource(user, resource):\n"
        "    if authorize(user, resource):\n"
        "        resource.delete()\n",
        encoding="utf-8",
    )
    return root


def _context() -> tuple[InitialEvidence, ...]:
    return (
        InitialEvidence.from_text(
            evidence_id="initial:policy",
            path="app/policy.py",
            content=(
                "def authorize(user, resource):\n"
                "    return user.tenant_id == resource.tenant_id\n"
            ),
        ),
    )


def _final_from_request(request, *, cite_expanded: bool):
    evidence_ids = ["initial:policy"]
    if cite_expanded:
        evidence_ids.append(request.caller_observations[0].evidence_id)
    return CallerTurn(
        action="FINAL",
        claims=(
            CallerClaimDraft(
                title="Destructive caller depends on shared authorization helper",
                message="The delete_resource caller relies on authorize before deletion.",
                category="security",
                severity="high",
                evidence_ids=tuple(evidence_ids),
                path="app/api.py",
                start_line=4,
            ),
        ),
    )


def test_tool_use_alone_does_not_claim_exploration_attribution(tmp_path):
    model = ScriptedModel(
        [
            CallerTurn(action="FIND_CALLERS", call_id="callers-1", symbol="authorize"),
            lambda request: _final_from_request(request, cite_expanded=False),
        ]
    )
    run = CallerExperiment().run(
        model=model,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=True,
    )

    assert run.status == "COMPLETED"
    assert run.tool_calls == 1
    payload = json.loads(run.observations[0].content)
    assert payload["tool"] == "find_callers"
    assert any(item["path"] == "app/api.py" for item in payload["call_sites"])
    assert run.claims[0].evidence_dependency == "initial_context_only"


def test_citing_find_callers_evidence_marks_prediction_as_exploration_dependent(tmp_path):
    model = ScriptedModel(
        [
            CallerTurn(action="FIND_CALLERS", call_id="callers-1", symbol="authorize"),
            lambda request: _final_from_request(request, cite_expanded=True),
        ]
    )
    run = CallerExperiment().run(
        model=model,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=True,
    )

    assert run.status == "COMPLETED"
    assert run.claims[0].evidence_dependency == "expanded_context_used"
    attribution = comparative_finding_evidence(run)
    assert attribution[0]["fingerprint"] == run.claims[0].finding.fingerprint
    assert attribution[0]["evidence_dependency"] == "expanded_context_used"
    assert attribution[0]["supported_claim"] is True
    assert attribution[0]["citation_correct"] is True


def test_static_variant_cannot_request_find_callers(tmp_path):
    model = ScriptedModel([CallerTurn(action="FIND_CALLERS", call_id="c1", symbol="authorize")])
    run = CallerExperiment().run(
        model=model,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=False,
    )
    assert run.status == "ERROR"
    assert run.tool_calls == 0
    assert run.claims == ()
    assert run.message == "find_callers_not_enabled_for_static_variant"


def test_unseen_evidence_is_rejected_and_failed_run_has_no_findings(tmp_path):
    model = ScriptedModel(
        [
            CallerTurn(
                action="FINAL",
                claims=(
                    CallerClaimDraft(
                        title="Unsupported",
                        message="Invented evidence cannot support this claim.",
                        category="bug",
                        severity="medium",
                        evidence_ids=("invented",),
                    ),
                ),
            )
        ]
    )
    run = CallerExperiment().run(
        model=model,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=False,
    )
    assert run.status == "ERROR"
    imported = advisory_import_from_caller_run(run)
    assert imported.status == "ERROR"
    assert imported.findings == ()
