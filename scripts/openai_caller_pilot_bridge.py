#!/usr/bin/env python3
"""Experiment-only OpenAI adapter for the blinded caller pilot bridge."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Mapping

BRIDGE_REQUEST_SCHEMA = "before-deploy-caller-bridge-request-v1"
BRIDGE_RESPONSE_SCHEMA = "before-deploy-caller-bridge-response-v1"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-5.6-sol"
DEFAULT_REASONING_EFFORT = "medium"
DEFAULT_TIMEOUT_SECONDS = 110

_MODEL_PRICING_USD_PER_MTOK = {
    "gpt-5.6": (Decimal("4"), Decimal("0.4"), Decimal("20")),
    "gpt-5.6-sol": (Decimal("4"), Decimal("0.4"), Decimal("20")),
}


def main() -> int:
    try:
        request = json.load(sys.stdin)
        response = invoke_openai(request)
    except Exception as error:
        print(f"openai caller pilot bridge failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    json.dump(response, sys.stdout, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


def invoke_openai(request: Any) -> Mapping[str, object]:
    if not isinstance(request, Mapping) or request.get("schema_version") != BRIDGE_REQUEST_SCHEMA:
        raise ValueError("unsupported caller bridge request schema")
    provider = _text(request.get("provider"), "provider")
    if provider != "openai":
        raise ValueError("OpenAI caller bridge requires provider='openai'")
    model = _text(request.get("model"), "model")
    expected_model = os.environ.get("OPENAI_MODEL", DEFAULT_MODEL).strip()
    if expected_model and model != expected_model:
        raise ValueError("caller bridge model does not match OPENAI_MODEL")
    allowed_actions = request.get("allowed_actions")
    if (
        not isinstance(allowed_actions, list)
        or not allowed_actions
        or not all(isinstance(item, str) and item in {"FINAL", "FIND_CALLERS"} for item in allowed_actions)
    ):
        raise ValueError("caller bridge allowed_actions is invalid")

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": (
                    "You are the blinded advisory reviewer in a controlled code-review experiment. "
                    "Use only evidence supplied in the user payload. Do not infer hidden repository "
                    "state, benchmark labels, expected defects, or evaluator intent. Report a claim "
                    "only when the supplied evidence concretely supports it. Cite evidence IDs exactly. "
                    "For a caller-dependent issue, request FIND_CALLERS only when it is available and "
                    "necessary. Return FINAL with an empty claims array when no concrete issue is supported."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(request, sort_keys=True, ensure_ascii=False),
            },
        ],
        "reasoning": {
            "effort": os.environ.get(
                "OPENAI_REASONING_EFFORT", DEFAULT_REASONING_EFFORT
            ).strip()
            or DEFAULT_REASONING_EFFORT,
        },
        "text": {
            "format": {
                "type": "json_schema",
                "name": "before_deploy_caller_pilot_turn",
                "strict": True,
                "schema": _response_schema(tuple(allowed_actions)),
            }
        },
        "max_output_tokens": _positive_env_int("OPENAI_MAX_OUTPUT_TOKENS", 4000),
        "store": False,
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    base_url = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/")
    if not base_url:
        raise ValueError("OPENAI_BASE_URL must not be empty")
    http_request = urllib.request.Request(
        f"{base_url}/responses",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    timeout = _positive_env_int("OPENAI_HTTP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
    try:
        with urllib.request.urlopen(http_request, timeout=timeout) as api_response:
            raw = api_response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"OpenAI Responses API returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError("OpenAI Responses API request failed") from error

    try:
        api_payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("OpenAI Responses API returned invalid JSON") from error
    if not isinstance(api_payload, Mapping):
        raise RuntimeError("OpenAI Responses API returned a non-object payload")

    turn = _extract_structured_turn(api_payload)
    usage = _usage(api_payload.get("usage"))
    result = dict(turn)
    result["schema_version"] = BRIDGE_RESPONSE_SCHEMA
    result["usage"] = usage
    return result


def _response_schema(allowed_actions: tuple[str, ...]) -> Mapping[str, object]:
    return {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": list(allowed_actions)},
            "call_id": {"type": ["string", "null"]},
            "symbol": {"type": ["string", "null"]},
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "message": {"type": "string"},
                        "category": {
                            "type": "string",
                            "enum": [
                                "bug",
                                "security",
                                "performance",
                                "maintainability",
                                "test",
                                "style",
                                "documentation",
                                "other",
                            ],
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "evidence_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "path": {"type": ["string", "null"]},
                        "start_line": {"type": ["integer", "null"]},
                        "end_line": {"type": ["integer", "null"]},
                        "confidence": {"type": ["string", "null"]},
                    },
                    "required": [
                        "title",
                        "message",
                        "category",
                        "severity",
                        "evidence_ids",
                        "path",
                        "start_line",
                        "end_line",
                        "confidence",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["action", "call_id", "symbol", "claims"],
        "additionalProperties": False,
    }


def _extract_structured_turn(payload: Mapping[str, object]) -> Mapping[str, object]:
    output = payload.get("output")
    if not isinstance(output, list):
        raise RuntimeError("OpenAI response has no output array")
    texts: list[str] = []
    for item in output:
        if not isinstance(item, Mapping) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, Mapping) and part.get("type") == "output_text":
                text = part.get("text")
                if isinstance(text, str) and text.strip():
                    texts.append(text)
    if len(texts) != 1:
        raise RuntimeError("OpenAI response must contain exactly one structured output_text")
    try:
        turn = json.loads(texts[0])
    except ValueError as error:
        raise RuntimeError("OpenAI structured output is not valid JSON") from error
    if not isinstance(turn, Mapping):
        raise RuntimeError("OpenAI structured output must be a JSON object")
    return turn


def _usage(value: Any) -> Mapping[str, int]:
    if not isinstance(value, Mapping):
        raise RuntimeError("OpenAI response has no usage object")
    input_tokens = _nonnegative_int(value.get("input_tokens"), "input_tokens")
    output_tokens = _nonnegative_int(value.get("output_tokens"), "output_tokens")
    details = value.get("input_tokens_details")
    cached_tokens = 0
    if isinstance(details, Mapping) and details.get("cached_tokens") is not None:
        cached_tokens = _nonnegative_int(details.get("cached_tokens"), "cached_tokens")
    if cached_tokens > input_tokens:
        raise RuntimeError("cached input tokens exceed input tokens")
    model = os.environ.get("OPENAI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    cost_microusd = _cost_microusd(
        model=model,
        input_tokens=input_tokens,
        cached_tokens=cached_tokens,
        output_tokens=output_tokens,
    )
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_microusd": cost_microusd,
    }


def _cost_microusd(
    *, model: str, input_tokens: int, cached_tokens: int, output_tokens: int
) -> int:
    pricing = _MODEL_PRICING_USD_PER_MTOK.get(model)
    if pricing is None:
        return 0
    input_rate, cached_rate, output_rate = pricing
    uncached = input_tokens - cached_tokens
    micro_usd = (
        Decimal(uncached) * input_rate
        + Decimal(cached_tokens) * cached_rate
        + Decimal(output_tokens) * output_rate
    )
    return int(micro_usd.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _positive_env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"OpenAI usage {label} must be a non-negative integer")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    return value.strip()


if __name__ == "__main__":
    raise SystemExit(main())
