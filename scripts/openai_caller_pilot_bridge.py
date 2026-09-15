#!/usr/bin/env python3
"""Experiment-only OpenAI adapter for the blinded caller pilot bridge."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Mapping

BRIDGE_REQUEST_SCHEMA = "before-deploy-caller-bridge-request-v1"
BRIDGE_RESPONSE_SCHEMA = "before-deploy-caller-bridge-response-v1"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_REASONING_EFFORT = "medium"
DEFAULT_TIMEOUT_SECONDS = 110
DEFAULT_CASES_PATH = "fixtures/caller-pilot-v1/cases.json"
PROTOCOL_REVISION = "caller-location-v2"

_MODEL_PRICING_USD_PER_MTOK = {
    "gpt-5.6": (Decimal("4"), Decimal("0.4"), Decimal("20")),
    "gpt-5.6-sol": (Decimal("4"), Decimal("0.4"), Decimal("20")),
    "gpt-5.6-luna": (Decimal("0.20"), Decimal("0.02"), Decimal("1.20")),
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

    blinded_request = _with_initial_source_ranges(request)
    constraints = _response_constraints(blinded_request)
    payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": (
                    "You are the blinded advisory reviewer in a controlled code-review experiment. "
                    "Use only evidence supplied in the user payload. Do not infer hidden repository "
                    "state, benchmark labels, expected defects, or evaluator intent. Cite evidence IDs "
                    "exactly. Use absolute repository source locations from supplied evidence metadata. "
                    "\n\n"
                    "Claim discipline. Report a claim only when the cited evidence shows the concrete "
                    "hazardous operation itself, and name that operation in the claim text. A name, "
                    "identifier, parameter, or shape that merely resembles a risky construct is not "
                    "evidence of one. The cited evidence must show the property you are claiming is "
                    "not enforced on the path you cite. A helper that does enforce the claimed "
                    "property, for example by canonicalizing or allowlisting input, binding values "
                    "through a parameterized interface, coercing a value into a bounded range, or "
                    "comparing secrets in constant time, is not a finding even when a caller passes "
                    "untrusted input to it. A claim must select one primary evidence ID that appears "
                    "in this payload; an optional secondary evidence ID may be selected when both "
                    "helper and caller evidence are material. A claim that cannot cite supplied "
                    "evidence must be omitted rather than weakened. "
                    "\n\n"
                    "Location contract. For an initial-context-only claim, locate the finding inside "
                    "that initial source range. For a claim whose concrete impact requires caller "
                    "evidence, locate the finding at the concrete caller operation or call site shown "
                    "in the cited caller observation, not at the helper definition. "
                    "\n\n"
                    "Expansion discipline. When the initial evidence alone concretely supports the "
                    "claim, return FINAL without expanding. Request FIND_CALLERS only when it is "
                    "available and necessary, that is when the helper's own evidence is neutral about "
                    "the claimed property and caller evidence is required to decide the claim. "
                    "\n\n"
                    "Return FINAL with an empty claims array when no concrete issue is supported. "
                    "Reporting nothing is a valid outcome and is preferred over a speculative claim."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(blinded_request, sort_keys=True, ensure_ascii=False),
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
                "schema": _response_schema(tuple(allowed_actions), **constraints),
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

    raw_turn = _extract_structured_turn(api_payload)
    turn = _normalize_turn(raw_turn, blinded_request, constraints)
    usage = _usage(api_payload.get("usage"))
    result = dict(turn)
    result["schema_version"] = BRIDGE_RESPONSE_SCHEMA
    result["usage"] = usage
    return result


def _with_initial_source_ranges(request: Mapping[str, object]) -> Mapping[str, object]:
    cases_path = Path(os.environ.get("CALLER_PILOT_CASES_PATH", DEFAULT_CASES_PATH))
    try:
        case_payload = json.loads(cases_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RuntimeError("caller pilot cases file is unavailable") from error
    except ValueError as error:
        raise RuntimeError("caller pilot cases file is invalid JSON") from error
    pilot = case_payload.get("pilot") if isinstance(case_payload, Mapping) else None
    raw_cases = pilot.get("cases") if isinstance(pilot, Mapping) else None
    if not isinstance(raw_cases, list):
        raise RuntimeError("caller pilot cases file has no cases array")

    source_ranges: dict[str, tuple[str, int, int, str]] = {}
    for raw in raw_cases:
        if not isinstance(raw, Mapping):
            continue
        case_id = raw.get("id")
        path = raw.get("initial_path")
        start = raw.get("initial_start_line")
        end = raw.get("initial_end_line")
        symbol = raw.get("symbol")
        if (
            isinstance(case_id, str)
            and case_id
            and isinstance(path, str)
            and path
            and isinstance(start, int)
            and not isinstance(start, bool)
            and start > 0
            and isinstance(end, int)
            and not isinstance(end, bool)
            and end >= start
            and isinstance(symbol, str)
            and symbol
        ):
            source_ranges[case_id] = (path, start, end, symbol)

    enriched = json.loads(json.dumps(request, sort_keys=True, ensure_ascii=False))
    if not isinstance(enriched, dict):
        raise RuntimeError("caller bridge request cannot be normalized")
    initial_context = enriched.get("initial_context")
    if not isinstance(initial_context, list) or len(initial_context) != 1:
        raise ValueError("caller pilot v2 requires exactly one initial evidence item")
    item = initial_context[0]
    if not isinstance(item, dict):
        raise ValueError("caller pilot initial evidence must be an object")
    evidence_id = item.get("evidence_id")
    path = item.get("path")
    if not isinstance(evidence_id, str) or not evidence_id.startswith("pilot-initial:"):
        raise ValueError("caller pilot initial evidence ID is invalid")
    case_id = evidence_id.removeprefix("pilot-initial:")
    source = source_ranges.get(case_id)
    if source is None:
        raise ValueError("caller pilot initial evidence has no blinded source range")
    expected_path, start, end, expected_symbol = source
    if path != expected_path:
        raise ValueError("caller pilot initial evidence path does not match blinded source range")

    tools = enriched.get("tools")
    if isinstance(tools, list) and tools:
        first_tool = tools[0]
        arguments = first_tool.get("arguments") if isinstance(first_tool, Mapping) else None
        tool_symbol = arguments.get("symbol") if isinstance(arguments, Mapping) else None
        if tool_symbol != expected_symbol:
            raise ValueError("caller pilot tool symbol does not match blinded source range")

    item["source_start_line"] = start
    item["source_end_line"] = end
    enriched["review_protocol"] = PROTOCOL_REVISION
    return enriched


def _response_constraints(request: Mapping[str, object]) -> Mapping[str, object]:
    evidence_ids: set[str] = set()
    paths: set[str] = set()
    lines: set[int] = set()

    initial_context = request.get("initial_context")
    if isinstance(initial_context, list):
        for raw in initial_context:
            if not isinstance(raw, Mapping):
                continue
            evidence_id = raw.get("evidence_id")
            path = raw.get("path")
            start = raw.get("source_start_line")
            end = raw.get("source_end_line")
            if isinstance(evidence_id, str) and evidence_id:
                evidence_ids.add(evidence_id)
            if isinstance(path, str) and path:
                paths.add(path)
            if (
                isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(end, int)
                and not isinstance(end, bool)
                and 0 < start <= end
            ):
                lines.update(range(start, end + 1))

    observations = request.get("caller_observations")
    if isinstance(observations, list):
        for raw in observations:
            if not isinstance(raw, Mapping):
                continue
            evidence_id = raw.get("evidence_id")
            if isinstance(evidence_id, str) and evidence_id:
                evidence_ids.add(evidence_id)
            content = raw.get("content")
            if not isinstance(content, str):
                continue
            try:
                payload = json.loads(content)
            except ValueError:
                continue
            call_sites = payload.get("call_sites") if isinstance(payload, Mapping) else None
            if not isinstance(call_sites, list):
                continue
            for site in call_sites:
                if not isinstance(site, Mapping):
                    continue
                path = site.get("path")
                if isinstance(path, str) and path:
                    paths.add(path)
                snippet = site.get("snippet")
                if isinstance(snippet, list):
                    for snippet_line in snippet:
                        if not isinstance(snippet_line, Mapping):
                            continue
                        line = snippet_line.get("line")
                        if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                            lines.add(line)
                line = site.get("line")
                if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                    lines.add(line)

    tool_symbol: str | None = None
    tools = request.get("tools")
    if isinstance(tools, list) and tools:
        first_tool = tools[0]
        arguments = first_tool.get("arguments") if isinstance(first_tool, Mapping) else None
        symbol = arguments.get("symbol") if isinstance(arguments, Mapping) else None
        if isinstance(symbol, str) and symbol:
            tool_symbol = symbol

    if not evidence_ids or not paths or not lines:
        raise ValueError("caller pilot response constraints require visible evidence locations")
    return {
        "evidence_ids": tuple(sorted(evidence_ids)),
        "paths": tuple(sorted(paths)),
        "lines": tuple(sorted(lines)),
        "tool_symbol": tool_symbol,
    }


def _response_schema(
    allowed_actions: tuple[str, ...],
    *,
    evidence_ids: tuple[str, ...],
    paths: tuple[str, ...],
    lines: tuple[int, ...],
    tool_symbol: str | None,
) -> Mapping[str, object]:
    symbol_values: list[object] = [None]
    if tool_symbol is not None:
        symbol_values.append(tool_symbol)
    return {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": list(allowed_actions)},
            "call_id": {"type": ["string", "null"]},
            "symbol": {"type": ["string", "null"], "enum": symbol_values},
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
                        "evidence_id": {"type": "string", "enum": list(evidence_ids)},
                        "secondary_evidence_id": {
                            "type": ["string", "null"],
                            "enum": [None, *evidence_ids],
                        },
                        "path": {
                            "type": ["string", "null"],
                            "enum": [None, *paths],
                            "description": "Repository-relative path where the concrete issue manifests.",
                        },
                        "start_line": {
                            "type": ["integer", "null"],
                            "enum": [None, *lines],
                            "description": "Absolute repository source line where the concrete issue manifests.",
                        },
                        "end_line": {
                            "type": ["integer", "null"],
                            "enum": [None, *lines],
                            "description": "Absolute repository source line where the concrete issue ends.",
                        },
                        "confidence": {"type": ["string", "null"]},
                    },
                    "required": [
                        "title",
                        "message",
                        "category",
                        "severity",
                        "evidence_id",
                        "secondary_evidence_id",
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


def _normalize_turn(
    turn: Mapping[str, object],
    request: Mapping[str, object],
    constraints: Mapping[str, object],
) -> Mapping[str, object]:
    action = turn.get("action")
    if action == "FIND_CALLERS":
        symbol = constraints.get("tool_symbol")
        if not isinstance(symbol, str) or not symbol:
            raise RuntimeError("FIND_CALLERS output has no visible allowed symbol")
        step = request.get("step")
        if isinstance(step, bool) or not isinstance(step, int) or step <= 0:
            raise RuntimeError("caller pilot request step is invalid")
        return {
            "action": "FIND_CALLERS",
            "call_id": f"call-{step}",
            "symbol": symbol,
            "claims": [],
        }
    if action != "FINAL":
        raise RuntimeError("OpenAI structured output action is invalid")

    raw_claims = turn.get("claims")
    if not isinstance(raw_claims, list):
        raise RuntimeError("OpenAI FINAL output has no claims array")
    claims: list[dict[str, object]] = []
    for raw in raw_claims:
        if not isinstance(raw, Mapping):
            continue
        title = raw.get("title")
        message = raw.get("message")
        if not isinstance(title, str) or not title.strip():
            continue
        if not isinstance(message, str) or not message.strip():
            continue
        primary = raw.get("evidence_id")
        if not isinstance(primary, str) or not primary:
            continue
        evidence_ids = [primary]
        secondary = raw.get("secondary_evidence_id")
        if isinstance(secondary, str) and secondary and secondary != primary:
            evidence_ids.append(secondary)

        path = raw.get("path")
        start = raw.get("start_line")
        end = raw.get("end_line")
        if not isinstance(path, str) or not path:
            path = None
            start = None
            end = None
        elif isinstance(start, int) and not isinstance(start, bool) and start > 0:
            if not isinstance(end, int) or isinstance(end, bool) or end <= 0:
                end = start
            elif end < start:
                start, end = end, start
        else:
            path = None
            start = None
            end = None

        confidence = raw.get("confidence")
        if isinstance(confidence, str):
            confidence = confidence.strip() or None
        elif confidence is not None:
            confidence = None

        claims.append(
            {
                "title": title.strip(),
                "message": message.strip(),
                "category": raw.get("category"),
                "severity": raw.get("severity"),
                "evidence_ids": evidence_ids,
                "path": path,
                "start_line": start,
                "end_line": end,
                "confidence": confidence,
            }
        )
    return {"action": "FINAL", "call_id": None, "symbol": None, "claims": claims}


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
