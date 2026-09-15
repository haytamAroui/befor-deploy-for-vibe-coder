import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path("scripts/openai_caller_pilot_bridge.py")


def _module():
    spec = importlib.util.spec_from_file_location("openai_caller_pilot_bridge", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(*, exploratory: bool):
    actions = ["FINAL", "FIND_CALLERS"] if exploratory else ["FINAL"]
    return {
        "schema_version": "before-deploy-caller-bridge-request-v1",
        "provider": "openai",
        "model": "gpt-5.6-luna",
        "step": 1,
        "task": "review",
        "authority": "ADVISORY",
        "gate_effect": "NONE",
        "allowed_actions": actions,
        "tools": (
            [{"name": "find_callers", "arguments": {"symbol": "target_url"}}]
            if exploratory
            else []
        ),
        "initial_context": [
            {
                "evidence_id": "pilot-initial:C-2JCP",
                "path": "helpers_b.py",
                "content_sha256": "hash",
                "content": "def target_url(request):\n    return request.query['url']\n",
            }
        ],
        "caller_observations": [],
        "response_contract": {},
    }


def _api_response(turn, *, input_tokens=100, cached_tokens=20, output_tokens=10):
    return {
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps(turn)}],
            }
        ],
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "input_tokens_details": {"cached_tokens": cached_tokens},
        },
    }


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_openai_bridge_uses_blinded_request_absolute_source_range_and_actual_usage(monkeypatch):
    module = _module()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    captured = {}

    turn = {
        "action": "FINAL",
        "call_id": None,
        "symbol": None,
        "claims": [],
    }

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return _FakeResponse(_api_response(turn))

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    result = module.invoke_openai(_request(exploratory=False))

    assert result["schema_version"] == "before-deploy-caller-bridge-response-v1"
    assert result["action"] == "FINAL"
    assert result["usage"] == {
        "input_tokens": 100,
        "output_tokens": 10,
        "cost_microusd": 28,
    }
    assert captured["request"].full_url == "https://api.openai.com/v1/responses"
    payload = json.loads(captured["request"].data.decode("utf-8"))
    assert payload["model"] == "gpt-5.6-luna"
    assert payload["store"] is False
    assert payload["reasoning"]["effort"] == "medium"
    assert payload["text"]["format"]["strict"] is True
    assert payload["text"]["format"]["schema"]["properties"]["action"]["enum"] == ["FINAL"]

    model_input = json.loads(payload["input"][1]["content"])
    assert model_input["review_protocol"] == "caller-location-v2"
    assert model_input["initial_context"][0]["source_start_line"] == 9
    assert model_input["initial_context"][0]["source_end_line"] == 10
    serialized = json.dumps(model_input, sort_keys=True)
    assert "case_class" not in serialized
    assert "defect_id" not in serialized
    assert "regions" not in serialized
    assert "FALSE-POSITIVE-TRAP" not in serialized
    assert "EXPLORATION-REQUIRED" not in serialized


def test_openai_bridge_exposes_find_callers_only_when_runner_allows_it(monkeypatch):
    module = _module()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    captured = {}

    turn = {
        "action": "FIND_CALLERS",
        "call_id": "call-1",
        "symbol": "target_url",
        "claims": [],
    }

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse(_api_response(turn, input_tokens=10, cached_tokens=0, output_tokens=5))

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    result = module.invoke_openai(_request(exploratory=True))

    assert result["action"] == "FIND_CALLERS"
    assert result["symbol"] == "target_url"
    assert captured["payload"]["text"]["format"]["schema"]["properties"]["action"]["enum"] == [
        "FINAL",
        "FIND_CALLERS",
    ]


def test_openai_bridge_rejects_model_mismatch_before_network(monkeypatch):
    module = _module()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    request = _request(exploratory=False)
    request["model"] = "other-model"

    with pytest.raises(ValueError, match="does not match OPENAI_MODEL"):
        module.invoke_openai(request)


def test_openai_bridge_rejects_unknown_initial_evidence_identity(monkeypatch):
    module = _module()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    request = _request(exploratory=False)
    request["initial_context"][0]["evidence_id"] = "pilot-initial:UNKNOWN"

    with pytest.raises(ValueError, match="no blinded source range"):
        module.invoke_openai(request)


def test_openai_bridge_cost_uses_luna_cached_input_rate():
    module = _module()
    assert module._cost_microusd(
        model="gpt-5.6-luna",
        input_tokens=100,
        cached_tokens=20,
        output_tokens=10,
    ) == 28
