"""Anthropic Messages API adapter for the bounded advisory agent runtime."""

from __future__ import annotations

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

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5"
DEFAULT_ANTHROPIC_PRICING = TokenPricing(
    input_microusd_per_token=5,
    output_microusd_per_token=25,
)


class AnthropicMessagesModel:
    """Provider adapter using current Messages API client tool-use blocks."""

    provider_id = "anthropic-messages"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        pricing: TokenPricing | None = None,
        timeout_seconds: int = 120,
        max_response_bytes: int = 4_000_000,
        max_output_tokens: int = 16_384,
        transport: JsonHttpTransport | None = None,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Anthropic API key must be non-empty")
        if not model.strip():
            raise ValueError("Anthropic model must be non-empty")
        if timeout_seconds <= 0 or max_response_bytes <= 0 or max_output_tokens <= 0:
            raise ValueError("Anthropic model bounds must be positive")
        if pricing is None and model != DEFAULT_ANTHROPIC_MODEL:
            raise ValueError("Explicit token pricing is required for non-default Anthropic models")
        self._api_key = api_key
        self._model = model
        self.pricing = pricing or DEFAULT_ANTHROPIC_PRICING
        self.pricing.validate()
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
            "system": system_instruction(),
            "messages": [
                {"role": "user", "content": render_model_input(request)},
            ],
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "input_schema": schema,
                }
                for name, description, schema in native_tool_specs()
            ],
            "tool_choice": {"type": "any"},
            "max_tokens": min(self.max_output_tokens, request.budget.max_output_tokens),
        }
        response = self.transport.post_json(
            ANTHROPIC_MESSAGES_URL,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": ANTHROPIC_API_VERSION,
                "content-type": "application/json",
            },
            payload=payload,
            timeout_seconds=self.timeout_seconds,
            max_response_bytes=self.max_response_bytes,
        )
        usage = _anthropic_usage(response, self.pricing)
        calls = _anthropic_calls(response)
        return parse_provider_calls(calls, usage=usage)


def _anthropic_usage(response: Mapping[str, Any], pricing: TokenPricing):
    raw = response.get("usage")
    if not isinstance(raw, Mapping):
        raise ValueError("Anthropic response is missing usage")
    return usage_from_counts(
        input_tokens=raw.get("input_tokens"),
        output_tokens=raw.get("output_tokens"),
        pricing=pricing,
    )


def _anthropic_calls(response: Mapping[str, Any]) -> tuple[tuple[str, str, Mapping[str, Any]], ...]:
    content = response.get("content")
    if not isinstance(content, list):
        raise ValueError("Anthropic response content must be an array")
    calls = []
    for block in content:
        if not isinstance(block, Mapping) or block.get("type") != "tool_use":
            continue
        call_id = block.get("id")
        name = block.get("name")
        arguments = block.get("input")
        if not isinstance(call_id, str) or not call_id.strip():
            raise ValueError("Anthropic tool use is missing id")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Anthropic tool use is missing name")
        if not isinstance(arguments, Mapping):
            raise ValueError("Anthropic tool-use input must be an object")
        calls.append((call_id, name, arguments))
    return tuple(calls)
