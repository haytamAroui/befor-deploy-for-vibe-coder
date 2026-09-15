import json

from before_deploy.agent_anthropic import AnthropicMessagesModel
from before_deploy.agent_model_common import TokenPricing
from before_deploy.agent_openai import OpenAIResponsesModel
from before_deploy.agent_orchestration import SpecialistSpec
from before_deploy.agent_routing import NativeModelRouter
from before_deploy.agent_runtime import AgentBudget, AgentContextItem, AgentModelInput


class FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post_json(self, url, *, headers, payload, timeout_seconds, max_response_bytes):
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "payload": payload,
                "timeout_seconds": timeout_seconds,
                "max_response_bytes": max_response_bytes,
            }
        )
        return self.response


def _request():
    return AgentModelInput(
        specialist="security",
        objective="Review authorization behavior.",
        step=1,
        budget=AgentBudget(),
        context=(
            AgentContextItem.from_text(
                evidence_id="context:auth",
                kind="changed-file",
                path="app/auth.py",
                content="def authorize(user):\n    return True\n",
            ),
        ),
        tool_results=(),
        prior_summaries=(),
    )


def _finalize_arguments():
    return {
        "claims": [
            {
                "title": "Authorization helper allows every user",
                "message": "The helper returns True unconditionally.",
                "category": "security",
                "severity": "high",
                "confidence": "high",
                "evidence_ids": ["context:auth"],
                "path": "app/auth.py",
                "start_line": 1,
                "end_line": 2,
                "assumptions": [],
            }
        ],
        "summary": "One evidence-supported authorization defect.",
    }


def test_openai_responses_adapter_parses_strict_finalize_call_and_usage_cost():
    transport = FakeTransport(
        {
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call-final",
                    "name": "finalize_review",
                    "arguments": json.dumps(_finalize_arguments()),
                }
            ],
            "usage": {"input_tokens": 100, "output_tokens": 20},
        }
    )
    model = OpenAIResponsesModel(api_key="secret", transport=transport)

    turn = model.complete(_request())

    assert turn.action == "FINAL"
    assert turn.claims[0].evidence_ids == ("context:auth",)
    assert turn.usage.input_tokens == 100
    assert turn.usage.output_tokens == 20
    assert turn.usage.cost_microusd == 2_000
    sent = transport.calls[0]
    assert sent["payload"]["model"] == "gpt-6-astra"
    assert sent["payload"]["tool_choice"] == "required"
    assert sent["payload"]["store"] is False
    assert any(tool["name"] == "finalize_review" for tool in sent["payload"]["tools"])
    assert sent["headers"]["Authorization"] == "Bearer secret"


def test_openai_responses_adapter_parses_repository_function_calls():
    transport = FakeTransport(
        {
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call-read",
                    "name": "read_file",
                    "arguments": json.dumps(
                        {"path": "app/policy.py", "start_line": None, "end_line": None}
                    ),
                }
            ],
            "usage": {"input_tokens": 30, "output_tokens": 10},
        }
    )
    model = OpenAIResponsesModel(api_key="secret", transport=transport)

    turn = model.complete(_request())

    assert turn.action == "TOOL"
    assert turn.tool_requests[0].call_id == "call-read"
    assert turn.tool_requests[0].tool_name == "read_file"
    assert turn.tool_requests[0].arguments == {"path": "app/policy.py"}


def test_anthropic_messages_adapter_parses_tool_use_finalize_and_usage_cost():
    transport = FakeTransport(
        {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu-final",
                    "name": "finalize_review",
                    "input": _finalize_arguments(),
                }
            ],
            "usage": {"input_tokens": 100, "output_tokens": 20},
        }
    )
    model = AnthropicMessagesModel(api_key="secret", transport=transport)

    turn = model.complete(_request())

    assert turn.action == "FINAL"
    assert turn.claims[0].severity == "high"
    assert turn.usage.cost_microusd == 1_000
    sent = transport.calls[0]
    assert sent["payload"]["model"] == "claude-opus-5"
    assert sent["payload"]["tool_choice"] == {"type": "any"}
    assert any(tool["name"] == "find_callers" for tool in sent["payload"]["tools"])
    assert sent["headers"]["x-api-key"] == "secret"


def test_native_adapters_require_explicit_pricing_for_non_default_models():
    try:
        OpenAIResponsesModel(api_key="secret", model="custom-openai-model")
    except ValueError as error:
        assert "pricing" in str(error)
    else:
        raise AssertionError("custom OpenAI models require price metadata")

    custom = AnthropicMessagesModel(
        api_key="secret",
        model="custom-anthropic-model",
        pricing=TokenPricing(3, 15),
        transport=FakeTransport({}),
    )
    assert custom.model_id == "custom-anthropic-model"


def test_provider_rejects_mixed_finalize_and_repository_calls():
    transport = FakeTransport(
        {
            "output": [
                {
                    "type": "function_call",
                    "call_id": "one",
                    "name": "search_symbol",
                    "arguments": json.dumps({"symbol": "authorize"}),
                },
                {
                    "type": "function_call",
                    "call_id": "two",
                    "name": "finalize_review",
                    "arguments": json.dumps(_finalize_arguments()),
                },
            ],
            "usage": {"input_tokens": 10, "output_tokens": 10},
        }
    )
    model = OpenAIResponsesModel(api_key="secret", transport=transport)

    try:
        model.complete(_request())
    except ValueError as error:
        assert "mixed" in str(error)
    else:
        raise AssertionError("finalization cannot be mixed with evidence collection")


class StubModel:
    def __init__(self, provider_id, model_id):
        self.provider_id = provider_id
        self.model_id = model_id

    def complete(self, request):
        raise AssertionError("routing test does not execute a model")


def test_native_model_router_is_deterministic_and_credential_free():
    openai = StubModel("openai-responses", "gpt-6-astra")
    anthropic = StubModel("anthropic-messages", "claude-opus-5")
    router = NativeModelRouter(
        {"primary": openai, "security": anthropic},
        default_route="primary",
        specialist_routes={"security": "security"},
        critic_route="primary",
    )
    security = SpecialistSpec("security", "Review security.", ("security",))
    general = SpecialistSpec("general", "Review general correctness.", ("general",))

    assert router.specialist_model(security) is anthropic
    assert router.specialist_model(general) is openai
    assert router.critic_model(security, None) is openai
    manifest = router.route_manifest()
    assert [(item.route_id, item.provider_id, item.model_id) for item in manifest] == [
        ("primary", "openai-responses", "gpt-6-astra"),
        ("security", "anthropic-messages", "claude-opus-5"),
    ]
