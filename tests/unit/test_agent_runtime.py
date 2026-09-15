from dataclasses import replace

from before_deploy.agent_runtime import (
    AGENT_AUTHORITY,
    AGENT_GATE_EFFECT,
    AGENT_RELEASE_STATUS,
    AgentBudget,
    AgentClaimDraft,
    AgentContextItem,
    AgentModelInput,
    AgentModelTurn,
    AgentRuntime,
    AgentToolRequest,
    AgentToolResult,
    AgentUsage,
)


class ScriptedModel:
    provider_id = "test-provider"
    model_id = "test-model"

    def __init__(self, turns):
        self.turns = list(turns)
        self.inputs: list[AgentModelInput] = []

    def complete(self, request):
        self.inputs.append(request)
        return self.turns.pop(0)


class ScriptedTools:
    def __init__(self):
        self.requests = []

    def execute(self, request, *, max_bytes):
        self.requests.append((request, max_bytes))
        return AgentToolResult.from_text(
            call_id=request.call_id,
            tool_name=request.tool_name,
            status="OK",
            content="def authorize(user):\n    return True\n",
        )


def _context():
    return (
        AgentContextItem.from_text(
            evidence_id="context:changed-auth",
            kind="changed-file",
            path="app/auth.py",
            content="def endpoint(user):\n    return authorize(user)\n",
        ),
    )


def test_agent_runtime_executes_bounded_tool_loop_and_cites_evidence():
    first = AgentModelTurn(
        action="TOOL",
        tool_requests=(
            AgentToolRequest(
                call_id="call-1",
                tool_name="read_file",
                arguments={"path": "app/policy.py"},
            ),
        ),
        usage=AgentUsage(input_tokens=100, output_tokens=20, cost_microusd=1000),
        summary="Need policy implementation before deciding whether authorization can be bypassed.",
    )
    tool_evidence = AgentToolResult.from_text(
        call_id="call-1",
        tool_name="read_file",
        status="OK",
        content="def authorize(user):\n    return True\n",
    ).evidence_id
    second = AgentModelTurn(
        action="FINAL",
        claims=(
            AgentClaimDraft(
                title="Authorization helper allows every caller",
                message="The changed endpoint delegates to a helper that returns True unconditionally.",
                category="security",
                severity="high",
                confidence="high",
                evidence_ids=("context:changed-auth", tool_evidence),
                path="app/policy.py",
                start_line=1,
                end_line=2,
            ),
        ),
        usage=AgentUsage(input_tokens=80, output_tokens=30, cost_microusd=1500),
    )
    model = ScriptedModel([first, second])
    tools = ScriptedTools()

    result = AgentRuntime().run(
        model=model,
        tools=tools,
        specialist="authorization",
        objective="Find authorization defects supported by repository evidence.",
        context=_context(),
    )

    assert result.status == "COMPLETED"
    assert result.authority == AGENT_AUTHORITY
    assert result.gate_effect == AGENT_GATE_EFFECT
    assert result.release_status == AGENT_RELEASE_STATUS
    assert result.tool_calls == 1
    assert result.usage == AgentUsage(input_tokens=180, output_tokens=50, cost_microusd=2500)
    assert len(result.claims) == 1
    assert result.claims[0].authority == AGENT_AUTHORITY
    assert result.claims[0].gate_effect == AGENT_GATE_EFFECT
    assert result.claims[0].claim_id.startswith("agent-claim:")
    assert set(result.claims[0].evidence_ids) == {"context:changed-auth", tool_evidence}
    assert result.run_sha256


def test_agent_runtime_rejects_claims_that_cite_unseen_evidence():
    model = ScriptedModel(
        [
            AgentModelTurn(
                action="FINAL",
                claims=(
                    AgentClaimDraft(
                        title="Unsupported claim",
                        message="This claim cites evidence the model never received.",
                        category="bug",
                        severity="medium",
                        confidence=None,
                        evidence_ids=("invented:evidence",),
                    ),
                ),
            )
        ]
    )

    result = AgentRuntime().run(
        model=model,
        tools=ScriptedTools(),
        specialist="correctness",
        objective="Review correctness.",
        context=_context(),
    )

    assert result.status == "ERROR"
    assert result.claims == ()
    assert result.gate_effect == "NONE"
    assert result.release_status == "NOT_EVALUATED"


def test_agent_runtime_fails_closed_when_model_attempts_invalid_turn_shape():
    model = ScriptedModel(
        [
            AgentModelTurn(
                action="FINAL",
                tool_requests=(
                    AgentToolRequest(call_id="forbidden", tool_name="release", arguments={}),
                ),
            )
        ]
    )

    result = AgentRuntime().run(
        model=model,
        tools=ScriptedTools(),
        specialist="general",
        objective="Review.",
        context=_context(),
    )

    assert result.status == "ERROR"
    assert result.claims == ()


def test_agent_runtime_enforces_usage_budget_before_accepting_claims():
    model = ScriptedModel(
        [
            AgentModelTurn(
                action="FINAL",
                claims=(
                    AgentClaimDraft(
                        title="Would otherwise be accepted",
                        message="Budget exhaustion must win before this claim is retained.",
                        category="bug",
                        severity="low",
                        confidence=None,
                        evidence_ids=("context:changed-auth",),
                    ),
                ),
                usage=AgentUsage(input_tokens=101),
            )
        ]
    )
    runtime = AgentRuntime(
        budget=AgentBudget(
            max_steps=2,
            max_tool_calls=2,
            max_tool_result_bytes=1024,
            max_input_tokens=100,
            max_output_tokens=100,
            max_cost_microusd=1000,
            max_duration_ms=10_000,
        )
    )

    result = runtime.run(
        model=model,
        tools=ScriptedTools(),
        specialist="general",
        objective="Review.",
        context=_context(),
    )

    assert result.status == "BUDGET_EXHAUSTED"
    assert result.claims == ()
    assert "input-token" in (result.message or "")


def test_agent_runtime_enforces_tool_call_budget():
    model = ScriptedModel(
        [
            AgentModelTurn(
                action="TOOL",
                tool_requests=(
                    AgentToolRequest(call_id="one", tool_name="read_file", arguments={"path": "a"}),
                    AgentToolRequest(call_id="two", tool_name="read_file", arguments={"path": "b"}),
                ),
            )
        ]
    )
    runtime = AgentRuntime(
        budget=AgentBudget(
            max_steps=2,
            max_tool_calls=1,
            max_tool_result_bytes=1024,
            max_input_tokens=1000,
            max_output_tokens=1000,
            max_cost_microusd=1000,
            max_duration_ms=10_000,
        )
    )

    result = runtime.run(
        model=model,
        tools=ScriptedTools(),
        specialist="general",
        objective="Review.",
        context=_context(),
    )

    assert result.status == "BUDGET_EXHAUSTED"
    assert result.tool_calls == 1
    assert result.claims == ()


def test_agent_context_hash_tampering_is_rejected_before_execution():
    context = _context()
    tampered = (replace(context[0], content="changed after hashing"),)
    model = ScriptedModel([AgentModelTurn(action="FINAL")])

    try:
        AgentRuntime().run(
            model=model,
            tools=ScriptedTools(),
            specialist="general",
            objective="Review.",
            context=tampered,
        )
    except ValueError as error:
        assert "hash mismatch" in str(error)
    else:
        raise AssertionError("tampered deterministic context should be rejected")
