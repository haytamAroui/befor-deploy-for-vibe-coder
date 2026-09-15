import json
import inspect
import sys
from pathlib import Path

import pytest

from before_deploy.caller_experiment import CallerModelInput
from before_deploy.caller_pilot import prepare_initial_evidence
from before_deploy.caller_pilot_runner import (
    BRIDGE_REQUEST_SCHEMA,
    BRIDGE_RESPONSE_SCHEMA,
    SubprocessCallerModel,
    _parse_bridge_response,
    _request_payload,
    execute_caller_pilot,
)


def test_bridge_request_contains_only_blinded_case_evidence_and_fixed_tool_boundary():
    cases_path = Path("fixtures/caller-pilot-v1/cases.json")
    _, case, evidence = prepare_initial_evidence(cases_path, "C-2JCP")
    payload = _request_payload(
        CallerModelInput(step=1, initial_context=(evidence,), caller_observations=()),
        provider="fixture-provider",
        model="fixture-model",
        enable_find_callers=True,
        allowed_symbol=case.symbol,
    )
    serialized = json.dumps(payload).lower()
    assert payload["schema_version"] == BRIDGE_REQUEST_SCHEMA
    assert payload["tools"] == [
        {
            "name": "find_callers",
            "description": "Return bounded lexical call sites and nearby context for the supplied symbol.",
            "arguments": {"symbol": "target_url"},
        }
    ]
    assert "exploration-required" not in serialized
    assert "static-sufficient" not in serialized
    assert "false-positive-trap" not in serialized
    assert "defect_id" not in serialized
    assert "regions" not in serialized


def test_bridge_rejects_find_callers_for_any_symbol_outside_case_boundary():
    response = {
        "schema_version": BRIDGE_RESPONSE_SCHEMA,
        "action": "FIND_CALLERS",
        "call_id": "call-1",
        "symbol": "another_symbol",
        "usage": {"input_tokens": 1, "output_tokens": 1, "cost_microusd": 0},
    }
    with pytest.raises(ValueError, match="outside the blinded case boundary"):
        _parse_bridge_response(
            response,
            enable_find_callers=True,
            allowed_symbol="target_url",
        )


def test_subprocess_bridge_uses_strict_json_protocol_and_accumulates_usage(tmp_path):
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        """
import json
import sys

request = json.load(sys.stdin)
evidence_id = request["initial_context"][0]["evidence_id"]
print(json.dumps({
    "schema_version": "before-deploy-caller-bridge-response-v1",
    "action": "FINAL",
    "claims": [{
        "title": "Concrete issue",
        "message": "The supplied evidence shows a concrete issue.",
        "category": "bug",
        "severity": "medium",
        "evidence_ids": [evidence_id]
    }],
    "usage": {
        "input_tokens": 7,
        "output_tokens": 5,
        "cost_microusd": 3
    }
}))
""".strip()
        + "\n",
        encoding="utf-8",
    )
    cases_path = Path("fixtures/caller-pilot-v1/cases.json")
    _, case, evidence = prepare_initial_evidence(cases_path, "C-2JCP")
    model = SubprocessCallerModel(
        command=(sys.executable, str(adapter.resolve())),
        provider="fixture-provider",
        model="fixture-model",
        enable_find_callers=False,
        allowed_symbol=case.symbol,
    )
    turn = model.complete(
        CallerModelInput(step=1, initial_context=(evidence,), caller_observations=())
    )
    assert turn.action == "FINAL"
    assert len(turn.claims) == 1
    assert turn.claims[0].evidence_ids == (evidence.evidence_id,)
    assert model.usage.input_tokens == 7
    assert model.usage.output_tokens == 5
    assert model.usage.cost_microusd == 3


def test_bridge_stderr_included_in_nonzero_exit_error(tmp_path):
    """Bridge stderr must appear in the RuntimeError when the bridge exits non-zero."""
    adapter = tmp_path / "failing_adapter.py"
    adapter.write_text(
        """
import sys
print("bridge error: OpenAI HTTP 429 rate-limited", file=sys.stderr)
sys.exit(1)
""".strip()
        + "\n",
        encoding="utf-8",
    )
    cases_path = Path("fixtures/caller-pilot-v1/cases.json")
    _, case, evidence = prepare_initial_evidence(cases_path, "C-2JCP")
    model = SubprocessCallerModel(
        command=(sys.executable, str(adapter.resolve())),
        provider="fixture-provider",
        model="fixture-model",
        enable_find_callers=False,
        allowed_symbol=case.symbol,
    )
    with pytest.raises(RuntimeError, match="429 rate-limited"):
        model.complete(
            CallerModelInput(step=1, initial_context=(evidence,), caller_observations=())
        )


def test_bridge_timeout_exceeds_http_default():
    """Runner default timeout must exceed the bridge's 110s HTTP default."""
    sig = inspect.signature(execute_caller_pilot)
    default = sig.parameters["timeout_seconds"].default
    assert default >= 110, (
        f"execute_caller_pilot timeout_seconds default ({default}) "
        f"must be >= bridge HTTP timeout (110)"
    )

