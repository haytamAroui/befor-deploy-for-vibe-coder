import importlib.util
import json
import sys
import urllib.error
from pathlib import Path

import pytest


SCRIPT = Path("scripts/production_openai_caller_pilot_bridge.py")


def _module():
    name = "production_openai_caller_pilot_bridge"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _http_error(code: int, *, retry_after: str | None = None):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return urllib.error.HTTPError("https://api.openai.com/v1/responses", code, "error", headers, None)


def test_transient_http_errors_retry_with_bounded_backoff():
    module = _module()
    calls = []
    sleeps = []
    outcomes = [_http_error(429, retry_after="0"), _http_error(503), object()]

    def opener(request, timeout):
        calls.append((request, timeout))
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    response = module._urlopen_with_retry(
        object(),
        10,
        opener=opener,
        policy=module.RetryPolicy(max_attempts=3, base_delay_ms=250, max_delay_ms=2_000),
        sleeper=sleeps.append,
    )

    assert response is not None
    assert len(calls) == 3
    assert sleeps == [0.0, 0.5]


def test_authentication_error_is_not_retried():
    module = _module()
    calls = 0

    def opener(request, timeout):
        nonlocal calls
        calls += 1
        raise _http_error(401)

    with pytest.raises(urllib.error.HTTPError) as raised:
        module._urlopen_with_retry(
            object(),
            10,
            opener=opener,
            policy=module.RetryPolicy(max_attempts=3),
            sleeper=lambda _: None,
        )
    assert raised.value.code == 401
    assert calls == 1


def test_transport_failure_retries_only_to_attempt_limit():
    module = _module()
    calls = 0

    def opener(request, timeout):
        nonlocal calls
        calls += 1
        raise urllib.error.URLError("temporary")

    with pytest.raises(urllib.error.URLError):
        module._urlopen_with_retry(
            object(),
            10,
            opener=opener,
            policy=module.RetryPolicy(max_attempts=3, base_delay_ms=1, max_delay_ms=1),
            sleeper=lambda _: None,
        )
    assert calls == 3


def test_cumulative_usage_ledger_records_luna_cost(tmp_path, monkeypatch):
    module = _module()
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    ledger = tmp_path / "usage.json"
    budget = module.UsageBudget(
        ledger_path=ledger,
        max_cost_microusd=1_000,
        max_input_tokens=1_000,
        max_output_tokens=1_000,
    )
    raw = json.dumps(
        {
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 20},
            }
        }
    ).encode()

    module._record_usage(budget, raw)
    assert json.loads(ledger.read_text()) == {
        "cost_microusd": 28,
        "input_tokens": 100,
        "output_tokens": 10,
        "responses": 1,
    }


def test_luna_cost_uses_same_half_up_rounding_as_canonical_bridge():
    module = _module()
    # 1 uncached input token + 4 output tokens = 5.0 micro-USD exactly.
    assert module._luna_cost_microusd(input_tokens=1, cached_tokens=0, output_tokens=4) == 5
    # 1 cached input + 4 output = 4.82 -> 5.
    assert module._luna_cost_microusd(input_tokens=1, cached_tokens=1, output_tokens=4) == 5


def test_cumulative_budget_fails_closed_and_does_not_commit_overage(tmp_path, monkeypatch):
    module = _module()
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    ledger = tmp_path / "usage.json"
    budget = module.UsageBudget(
        ledger_path=ledger,
        max_cost_microusd=20,
        max_input_tokens=None,
        max_output_tokens=None,
    )
    raw = json.dumps(
        {
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {"cached_tokens": 20},
            }
        }
    ).encode()

    with pytest.raises(RuntimeError, match="cost budget exhausted"):
        module._record_usage(budget, raw)
    assert not ledger.exists()


def test_precheck_stops_before_next_request_when_budget_is_at_limit(tmp_path):
    module = _module()
    ledger = tmp_path / "usage.json"
    ledger.write_text(
        json.dumps({"input_tokens": 10, "output_tokens": 5, "cost_microusd": 20, "responses": 1})
    )
    budget = module.UsageBudget(
        ledger_path=ledger,
        max_cost_microusd=20,
        max_input_tokens=None,
        max_output_tokens=None,
    )

    with pytest.raises(RuntimeError, match="cost budget exhausted"):
        module._budget_precheck(budget)
