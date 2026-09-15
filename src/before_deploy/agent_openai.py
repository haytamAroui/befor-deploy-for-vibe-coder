"""OpenAI Responses API adapter for the bounded advisory agent runtime."""

from __future__ import annotations

import json
from typing import Any, Mapping

from before_deploy.agent_model_common import (
    JsonHttpTransport,
    TokenPricing,
    UrllibJsonTransport,
    native_tool_specs,
    parse_provider_calls,
    render_model_input,
    system_instruction,
    usage_from_counts,
)
from before_deploy.agent_runtime import AgentModelInput, AgentModelTurn

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_OPENAI_MODEL = "gpt-6-astra"
DEFAULT_OPENAI_PRICING = TokenPricing(
    input_microusd_per_token=10,
    output_microusd_per_token=50,
)
_OPENAI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})


class OpenAIResponsesModel:
    """Provider adapter using current Responses API client-side function calls."""

    provider_id = "openai-responses"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = DEFAULT_OPENAI_MODEL,
        pricing: TokenPricing | None = None,
        reasoning_effort: str = "high",
        timeout_seconds: int = 120,
        max_response_bytes: int = 4_000_000,
        max_output_tokens: int = 16_384,
        transport: JsonHttpTransport | None = None,
    ) -> None:
        if not api_key.strip():
            raise ValueError("OpenAI API key must be non-empty")
        if not model.strip():
            raise ValueError("OpenAI model must be non-empty")
        if reasoning_effort not in _OPENAI_REASONING_EFFORTS:
            raise ValueError("Unsupported OpenAI reasoning effort")
        if timeout_seconds <= 0 or max_response_bytes <= 0 or max_output_tokens <= 0:
            raise ValueError("OpenAI model bounds must be positive")
        if pricing is None and model != DEFAULT_OPENAI_MODEL:
            raise ValueError("Explicit token pricing is required for non-default OpenAI models")
        self._api_key = api_key
        self._model = model
        self.pricing = pricing or DEFAULT_OPENAI_PRICING
        self.pricing.validate()
        self.reasoning_effort = reasoning_effort
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_output_tokens = max_output_tokens
        self.transport = transport or UrllibJsonTransport()

    @property
    def model_id(self) -> str:
        return self._model

    def complete(self, request: AgentModelInput) -> AgentModelTurn:
        payload: dict[str, Any] = {
            "model": self._model,
            "input": [
                {"role": "system", "content": system_instruction()},
                {"role": "user", "content": render_model_input(request)},
            ],
            "tools": [
                {
                    "type": "function",
                    "name": name,
                    "description": description,
                    "parameters": schema,
                    "strict": True,
                }
                for name, description, schema in native_tool_specs()
            ],
            "tool_choice": "required",
            "parallel_tool_calls": True,
            "max_output_tokens": min(self.max_output_tokens, request.budget.max_output_tokens),
            "reasoning": {"effort": self.reasoning_effort},
            "store": False,
        }
        response = self.transport.post_json(
            OPENAI_RESPONSES_URL,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            payload=payload,
            timeout_seconds=self.timeout_seconds,
            max_response_bytes=self.max_response_bytes,
        )
        usage = _openai_usage(response, self.pricing)
        calls = _openai_calls(response)
        return parse_provider_calls(calls, usage=usage)


def _openai_usage(response: Mapping[str, Any], pricing: TokenPricing):
    raw = response.get("usage")
    if not isinstance(raw, Mapping):
        raise ValueError("OpenAI response is missing usage")
    return usage_from_counts(
        input_tokens=raw.get("input_tokens"),
        output_tokens=raw.get("output_tokens"),
        pricing=pricing,
    )


def _openai_calls(response: Mapping[str, Any]) -> tuple[tuple[str, str, Mapping[str, Any]], ...]:
    output = response.get("output")
    if not isinstance(output, list):
        raise ValueError("OpenAI response output must be an array")
    calls = []
    for item in output:
        if not isinstance(item, Mapping) or item.get("type") != "function_call":
            continue
        call_id = item.get("call_id")
        name = item.get("name")
        raw_arguments = item.get("arguments")
        if not isinstance(call_id, str) or not call_id.strip():
            raise ValueError("OpenAI function call is missing call_id")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("OpenAI function call is missing name")
        if not isinstance(raw_arguments, str):
            raise ValueError("OpenAI function-call arguments must be JSON text")
        try:
            arguments = json.loads(raw_arguments)
        except ValueError as error:
            raise ValueError("OpenAI function-call arguments are invalid JSON") from error
        if not isinstance(arguments, Mapping):
            raise ValueError("OpenAI function-call arguments must decode to an object")
        calls.append((call_id, name, arguments))
    return tuple(calls)
