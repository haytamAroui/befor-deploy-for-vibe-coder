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
        return self.turns.pop(0)


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


def test_find_callers_is_the_only_dynamic_evidence_and_dependency_is_derived(tmp_path):
    probe = ScriptedModel([CallerTurn(action="FIND_CALLERS", call_id="c1", symbol="authorize")])
    first = CallerExperiment().run(
        model=probe,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=True,
    )
    assert first.status == "ERROR" or first.status == "BUDGET_EXHAUSTED"
    observation = probe.inputs[-1].caller_observations if len(probe.inputs) > 1 else ()
    # Use the real first observation ID from a complete two-turn execution below.

    model = ScriptedModel(
        [
            CallerTurn(action="FIND_CALLERS", call_id="callers-1", symbol="authorize"),
            CallerTurn(
                action="FINAL",
                claims=(
                    CallerClaimDraft(
                        title="Destructive caller depends on shared authorization helper",
                        message="The delete_resource caller relies on authorize before deletion.",
                        category="security",
                        severity="high",
                        evidence_ids=("initial:policy",),
                        path="app/api.py",
                        start_line=4,
                    ),
                ),
            ),
        ]
    )
    # The scripted final claim initially cites only static evidence, so Before Deploy must not
    # claim exploration attribution merely because the tool happened to run.
    run = CallerExperiment().run(
        model=model,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=True,
    )
    assert run.status == "COMPLETED"
    assert run.tool_calls == 1
    assert json.loads(run.observations[0].content)["tool"] == "find_callers"
    assert any(item["path"] == "app/api.py" for item in json.loads(run.observations[0].content)["call_sites"])
    assert run.claims[0].evidence_dependency == "initial_context_only"

    evidence_id = run.observations[0].evidence_id
    model_with_dependency = ScriptedModel(
        [
            CallerTurn(action="FIND_CALLERS", call_id="callers-1", symbol="authorize"),
            CallerTurn(
                action="FINAL",
                claims=(
                    CallerClaimDraft(
                        title="Destructive caller depends on shared authorization helper",
                        message="The delete_resource caller relies on authorize before deletion.",
                        category="security",
                        severity="high",
                        evidence_ids=("initial:policy", evidence_id),
                        path="app/api.py",
                        start_line=4,
                    ),
                ),
            ),
        ]
    )
    expanded = CallerExperiment().run(
        model=model_with_dependency,
        repository=_repo(tmp_path),
        initial_context=_context(),
        enable_find_callers=True,
    )
    assert expanded.status == "COMPLETED"
    assert expanded.claims[0].evidence_dependency == "expanded_context_used"
    attribution = comparative_finding_evidence(expanded)
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
    assert imported.gate_effect if hasattr(imported, "gate_effect") else True
