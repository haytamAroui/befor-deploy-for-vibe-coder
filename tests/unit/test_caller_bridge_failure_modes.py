"""Operational failure-mode evidence for the OpenAI caller bridge.

These tests are the named verifiers in the frozen operational scenario map in
``before_deploy.readiness_gate``. Renaming or deleting one silently removes a
release-gate scenario, so the map and this module must change together.
"""

import importlib.util
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path("scripts/openai_caller_pilot_bridge.py")
CASES = "fixtures/caller-pilot-v1/cases.json"


def _module():
    spec = importlib.util.spec_from_file_location(
        "openai_caller_pilot_bridge_failure_modes", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request() -> dict[str, Any]:
    return {
        "schema_version": "before-deploy-caller-bridge-request-v1",
        "provider": "openai",
        "model": "gpt-5.6-luna",
        "step": 1,
        "task": "review",
        "authority": "ADVISORY",
        "gate_effect": "NONE",
        "allowed_actions": ["FINAL"],
        "tools": [],
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


def _prepare_environment(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    monkeypatch.setenv("CALLER_PILOT_CASES_PATH", CASES)


class _RawResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_RawResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def test_bridge_requires_api_key_and_makes_no_network_request_when_absent(monkeypatch):
    module = _module()
    _prepare_environment(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    calls: list[object] = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        raise AssertionError("bridge must not reach the network without a credential")

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY is not configured"):
        module.invoke_openai(_request())
    assert calls == []


@pytest.mark.parametrize("body", [b"not json", b"[]"])
def test_bridge_fails_closed_on_malformed_api_payload(monkeypatch, body):
    module = _module()
    _prepare_environment(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda request, timeout: _RawResponse(body),
    )

    with pytest.raises(RuntimeError, match="invalid JSON|non-object payload"):
        module.invoke_openai(_request())
