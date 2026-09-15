#!/usr/bin/env python3
"""Production-hardening wrapper around the blinded OpenAI caller-pilot bridge.

The underlying bridge owns the blinded request/response contract. This wrapper adds
operational policy only: bounded retries for transient transport failures, a stable
client request ID for support correlation, and an optional cumulative usage ledger.
"""

from __future__ import annotations

import importlib.util
import json
import os
import time
import urllib.error
import uuid
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Mapping

DELEGATE = Path(__file__).with_name("openai_caller_pilot_bridge.py")
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY_MS = 250
DEFAULT_RETRY_MAX_DELAY_MS = 2_000
_RETRYABLE_HTTP = {408, 409, 429, 500, 502, 503, 504}
_LUNA_INPUT_RATE = Decimal("0.20")
_LUNA_CACHED_INPUT_RATE = Decimal("0.02")
_LUNA_OUTPUT_RATE = Decimal("1.20")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_delay_ms: int = DEFAULT_RETRY_BASE_DELAY_MS
    max_delay_ms: int = DEFAULT_RETRY_MAX_DELAY_MS

    @classmethod
    def from_env(cls) -> "RetryPolicy":
        value = cls(
            max_attempts=_positive_env_int("BEFORE_DEPLOY_PROVIDER_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
            base_delay_ms=_positive_env_int(
                "BEFORE_DEPLOY_PROVIDER_RETRY_BASE_DELAY_MS", DEFAULT_RETRY_BASE_DELAY_MS
            ),
            max_delay_ms=_positive_env_int(
                "BEFORE_DEPLOY_PROVIDER_RETRY_MAX_DELAY_MS", DEFAULT_RETRY_MAX_DELAY_MS
            ),
        )
        if value.base_delay_ms > value.max_delay_ms:
            raise ValueError("provider retry base delay cannot exceed max delay")
        return value


@dataclass(frozen=True)
class UsageBudget:
    ledger_path: Path | None
    max_cost_microusd: int | None
    max_input_tokens: int | None
    max_output_tokens: int | None

    @classmethod
    def from_env(cls) -> "UsageBudget":
        ledger_raw = os.environ.get("BEFORE_DEPLOY_BUDGET_LEDGER", "").strip()
        limits = {
            "max_cost_microusd": _optional_positive_env_int("BEFORE_DEPLOY_MAX_COST_MICROUSD"),
            "max_input_tokens": _optional_positive_env_int("BEFORE_DEPLOY_MAX_INPUT_TOKENS"),
            "max_output_tokens": _optional_positive_env_int("BEFORE_DEPLOY_MAX_OUTPUT_TOKENS_TOTAL"),
        }
        ledger = Path(ledger_raw) if ledger_raw else None
        if any(value is not None for value in limits.values()) and ledger is None:
            raise ValueError("cumulative provider budgets require BEFORE_DEPLOY_BUDGET_LEDGER")
        return cls(ledger_path=ledger, **limits)


class _BudgetedResponse:
    def __init__(self, response: Any, budget: UsageBudget) -> None:
        self._response = response
        self._budget = budget
        self._raw: bytes | None = None

    def __enter__(self):
        entered = self._response.__enter__() if hasattr(self._response, "__enter__") else self._response
        if entered is not self._response:
            self._response = entered
        return self

    def __exit__(self, exc_type, exc, tb):
        if hasattr(self._response, "__exit__"):
            return self._response.__exit__(exc_type, exc, tb)
        return False

    def read(self) -> bytes:
        if self._raw is None:
            raw = self._response.read()
            if not isinstance(raw, bytes):
                raise RuntimeError("OpenAI response body must be bytes")
            _record_usage(self._budget, raw)
            self._raw = raw
        return self._raw

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)


def main() -> int:
    delegate = _load_delegate()
    retry_policy = RetryPolicy.from_env()
    usage_budget = UsageBudget.from_env()
    opener = delegate.urllib.request.urlopen
    client_request_id = os.environ.get("BEFORE_DEPLOY_CLIENT_REQUEST_ID", "").strip() or str(uuid.uuid4())

    def hardened_urlopen(request, timeout):
        _budget_precheck(usage_budget)
        if request.get_header("X-client-request-id") is None:
            request.add_header("X-Client-Request-Id", client_request_id)
        response = _urlopen_with_retry(
            request,
            timeout,
            opener=opener,
            policy=retry_policy,
            sleeper=time.sleep,
        )
        return _BudgetedResponse(response, usage_budget)

    delegate.urllib.request.urlopen = hardened_urlopen
    return delegate.main()


def _load_delegate():
    spec = importlib.util.spec_from_file_location("before_deploy_openai_caller_delegate", DELEGATE)
    if spec is None or spec.loader is None:
        raise RuntimeError("OpenAI caller bridge delegate could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _urlopen_with_retry(
    request,
    timeout: int,
    *,
    opener: Callable[..., Any],
    policy: RetryPolicy,
    sleeper: Callable[[float], None],
):
    last_error: BaseException | None = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return opener(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code not in _RETRYABLE_HTTP or attempt >= policy.max_attempts:
                raise
            sleeper(_retry_delay_seconds(attempt, policy, error))
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt >= policy.max_attempts:
                raise
            sleeper(_retry_delay_seconds(attempt, policy, None))
    assert last_error is not None
    raise last_error


def _retry_delay_seconds(
    attempt: int,
    policy: RetryPolicy,
    error: urllib.error.HTTPError | None,
) -> float:
    if error is not None and error.headers is not None:
        raw = error.headers.get("Retry-After")
        if raw is not None:
            try:
                seconds = float(raw)
            except (TypeError, ValueError):
                seconds = -1.0
            if seconds >= 0:
                return min(seconds, policy.max_delay_ms / 1000)
    delay_ms = min(policy.base_delay_ms * (2 ** max(0, attempt - 1)), policy.max_delay_ms)
    return delay_ms / 1000


def _budget_precheck(budget: UsageBudget) -> None:
    if budget.ledger_path is None:
        return
    totals = _read_ledger(budget.ledger_path)
    _assert_budget(totals, budget, allow_equal=False)


def _record_usage(budget: UsageBudget, raw: bytes) -> None:
    if budget.ledger_path is None:
        return
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        # The delegate owns malformed-response handling. Do not mutate accounting
        # when usage cannot be authenticated from a valid provider response object.
        return
    if not isinstance(payload, Mapping):
        return
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        return
    input_tokens = _nonnegative_int(usage.get("input_tokens"), "input_tokens")
    output_tokens = _nonnegative_int(usage.get("output_tokens"), "output_tokens")
    details = usage.get("input_tokens_details")
    cached_tokens = 0
    if isinstance(details, Mapping) and details.get("cached_tokens") is not None:
        cached_tokens = _nonnegative_int(details.get("cached_tokens"), "cached_tokens")
    if cached_tokens > input_tokens:
        raise RuntimeError("cached input tokens exceed input tokens")

    model = os.environ.get("OPENAI_MODEL", "gpt-5.6-luna").strip() or "gpt-5.6-luna"
    if model != "gpt-5.6-luna":
        raise RuntimeError("production caller bridge budget supports only gpt-5.6-luna")
    cost_microusd = _luna_cost_microusd(
        input_tokens=input_tokens,
        cached_tokens=cached_tokens,
        output_tokens=output_tokens,
    )

    totals = _read_ledger(budget.ledger_path)
    updated = {
        "input_tokens": totals["input_tokens"] + input_tokens,
        "output_tokens": totals["output_tokens"] + output_tokens,
        "cost_microusd": totals["cost_microusd"] + cost_microusd,
        "responses": totals["responses"] + 1,
    }
    _assert_budget(updated, budget, allow_equal=True)
    _write_ledger(budget.ledger_path, updated)


def _luna_cost_microusd(*, input_tokens: int, cached_tokens: int, output_tokens: int) -> int:
    if cached_tokens > input_tokens:
        raise RuntimeError("cached input tokens exceed input tokens")
    uncached = input_tokens - cached_tokens
    value = (
        Decimal(uncached) * _LUNA_INPUT_RATE
        + Decimal(cached_tokens) * _LUNA_CACHED_INPUT_RATE
        + Decimal(output_tokens) * _LUNA_OUTPUT_RATE
    )
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _assert_budget(totals: Mapping[str, int], budget: UsageBudget, *, allow_equal: bool) -> None:
    checks = (
        ("cost_microusd", budget.max_cost_microusd, "cost"),
        ("input_tokens", budget.max_input_tokens, "input token"),
        ("output_tokens", budget.max_output_tokens, "output token"),
    )
    for field, limit, label in checks:
        if limit is None:
            continue
        value = totals[field]
        exceeded = value > limit if allow_equal else value >= limit
        if exceeded:
            raise RuntimeError(f"cumulative provider {label} budget exhausted")


def _read_ledger(path: Path) -> dict[str, int]:
    if not path.exists():
        return {"input_tokens": 0, "output_tokens": 0, "cost_microusd": 0, "responses": 0}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError("provider budget ledger is unreadable") from error
    if not isinstance(value, Mapping):
        raise RuntimeError("provider budget ledger must be a JSON object")
    return {
        field: _nonnegative_int(value.get(field), field)
        for field in ("input_tokens", "output_tokens", "cost_microusd", "responses")
    }


def _write_ledger(path: Path, totals: Mapping[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(dict(totals), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


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


def _optional_positive_env_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"provider usage {label} must be a non-negative integer")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
