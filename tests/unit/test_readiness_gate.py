"""Tests for the release-blocking readiness gate."""

import ast
import json
from pathlib import Path

import pytest

from before_deploy.caller_pilot import CALLER_PILOT_RESULT_SCHEMA
from before_deploy.production_readiness import ProductionReadinessEvidence
from before_deploy.readiness_gate import (
    ASSURANCE_WORKFLOW_TESTS,
    CLEAN_INSTALL_SMOKE_TESTS,
    OPERATIONAL_SCENARIO_TESTS,
    CaseOutcome,
    GateInputs,
    ReadinessGateError,
    evaluate_release_gate,
    main,
    parse_junit_outcomes,
    resolve_scenario,
)
from before_deploy.real_world_validation import REAL_WORLD_VALIDATION_SCHEMA

ALL_OPERATIONAL_VERIFIERS = tuple(
    node for group in OPERATIONAL_SCENARIO_TESTS.values() for node in group
)


def _dotted(node_id: str) -> tuple[str, str]:
    path, _, name = node_id.partition("::")
    return path[:-3].replace("/", "."), name


def _case(classname: str, name: str, outcome: str = "passed") -> str:
    if outcome == "passed":
        return f'<testcase classname="{classname}" name="{name}" time="0.01"/>'
    return (
        f'<testcase classname="{classname}" name="{name}" time="0.01">'
        f"<{outcome}/></testcase>"
    )


def _write_junit(path: Path, cases) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(cases)
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<testsuites><testsuite name="pytest" tests="{len(cases)}">'
        f"{body}</testsuite></testsuites>\n",
        encoding="utf-8",
    )
    return path


def _cases_for(node_ids, outcomes) -> list[str]:
    cases = []
    for node_id in node_ids:
        classname, name = _dotted(node_id)
        cases.append(_case(classname, name, outcomes.get(node_id, "passed")))
    return cases


def _pilot_report(path: Path, *, decision: str = "GO") -> Path:
    payload = {
        "schema_version": CALLER_PILOT_RESULT_SCHEMA,
        "caller_pilot": {
            "decision": decision,
            "exploration_required_recall_lift": 0.775,
            "false_positive_trap_rate_delta": 0.0,
            "static_sufficient_recall_delta": 0.0,
            "static_variant": {"run_count": 5},
            "exploratory_variant": {
                "run_count": 5,
                "exploration_attributable_tp": 31,
                "exploration_attributable_fp": 21,
                "supported_claim_rate": 1.0,
                "citation_correct_rate": 1.0,
                "prediction_stability": 1.0,
                "exact_prediction_stability": 0.0,
                "mean_latency_ms": 161170.0,
                "mean_cost_microusd": 16400.0,
            },
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _real_world_report(path: Path) -> Path:
    payload = {
        "schema_version": REAL_WORLD_VALIDATION_SCHEMA,
        "real_world_validation": {
            "name": "rw",
            "decision": "PASS",
            "reason_codes": [],
            "repository_count": 3,
            "known_defects": 6,
            "detected_defects": 4,
            "recall": 0.667,
            "exploration_attributable_tp": 7,
            "exploration_attributable_fp": 2,
            "static_false_positive_rate": 0.05,
            "exploratory_false_positive_rate": 0.05,
            "blinded": True,
            "independent": True,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _complete_inputs(
    tmp_path: Path,
    *,
    decision: str = "GO",
    operational_outcomes=None,
    assurance_outcomes=None,
    smoke_outcomes=None,
    full_suite_cases=None,
) -> GateInputs:
    full_cases = (
        full_suite_cases
        if full_suite_cases is not None
        else [_case("tests.unit.test_scan", "test_blocks")]
    )
    return GateInputs(
        pilot_report=_pilot_report(tmp_path / "caller-pilot.json", decision=decision),
        real_world_report=_real_world_report(tmp_path / "real-world-validation.json"),
        operational_report=_write_junit(
            tmp_path / "operational.xml",
            _cases_for(ALL_OPERATIONAL_VERIFIERS, operational_outcomes or {}),
        ),
        assurance_report=_write_junit(
            tmp_path / "assurance.xml",
            _cases_for(ASSURANCE_WORKFLOW_TESTS, assurance_outcomes or {}),
        ),
        smoke_report=_write_junit(
            tmp_path / "smoke.xml",
            _cases_for(CLEAN_INSTALL_SMOKE_TESTS, smoke_outcomes or {}),
        ),
        full_suite_report=_write_junit(tmp_path / "full.xml", full_cases),
    )


def _argv(inputs: GateInputs, output_dir: Path | None = None) -> list[str]:
    argv = [
        "--pilot-report", str(inputs.pilot_report),
        "--real-world-report", str(inputs.real_world_report),
        "--operational-report", str(inputs.operational_report),
        "--assurance-report", str(inputs.assurance_report),
        "--smoke-report", str(inputs.smoke_report),
        "--full-suite-report", str(inputs.full_suite_report),
    ]
    if output_dir is not None:
        argv += ["--output-dir", str(output_dir)]
    return argv


def test_operational_scenario_keys_are_readiness_evidence_fields():
    fields = set(ProductionReadinessEvidence.__dataclass_fields__)
    assert set(OPERATIONAL_SCENARIO_TESTS) <= fields


def test_every_declared_verifier_exists_in_the_repository():
    declared = [
        *ALL_OPERATIONAL_VERIFIERS,
        *ASSURANCE_WORKFLOW_TESTS,
        *CLEAN_INSTALL_SMOKE_TESTS,
    ]
    for node_id in declared:
        source_path, _, name = node_id.partition("::")
        source = Path(source_path)
        assert source.is_file(), f"{node_id!r} points at a missing file"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        functions = {
            item.name for item in ast.walk(tree) if isinstance(item, ast.FunctionDef)
        }
        assert name in functions, f"{node_id!r} points at a renamed or deleted test"


def test_verifier_absent_from_report_is_an_input_error_not_a_pass():
    outcomes = (CaseOutcome("tests.unit.test_other::test_z", "passed"),)
    with pytest.raises(ReadinessGateError, match="no result"):
        resolve_scenario(["tests/unit/test_x.py::test_y"], outcomes, scenario="demo")


def test_failed_or_skipped_verifier_is_not_a_pass():
    declared = ["tests/unit/test_x.py::test_y"]
    for status in ("failed", "skipped"):
        outcomes = (CaseOutcome("tests.unit.test_x::test_y", status),)
        assert resolve_scenario(declared, outcomes, scenario="demo") is False


def test_junit_parser_treats_only_clean_cases_as_passed(tmp_path):
    path = _write_junit(
        tmp_path / "mixed.xml",
        [
            _case("tests.unit.test_x", "test_ok"),
            _case("tests.unit.test_x", "test_bad", "failure"),
            _case("tests.unit.test_x", "test_skip", "skipped"),
        ],
    )
    outcomes = {item.node_id: item.status for item in parse_junit_outcomes(path)}
    assert outcomes == {
        "tests.unit.test_x::test_ok": "passed",
        "tests.unit.test_x::test_bad": "failed",
        "tests.unit.test_x::test_skip": "skipped",
    }


def test_parametrized_verifier_requires_every_case_to_pass(tmp_path):
    path = _write_junit(
        tmp_path / "params.xml",
        [
            _case("tests.unit.test_x", "test_y[a]"),
            _case("tests.unit.test_x", "test_y[b]", "failure"),
        ],
    )
    outcomes = parse_junit_outcomes(path)
    assert resolve_scenario(["tests/unit/test_x.py::test_y"], outcomes, scenario="demo") is False


def test_complete_evidence_yields_ready_and_records_every_digest(tmp_path):
    result = evaluate_release_gate(_complete_inputs(tmp_path))
    assert result.readiness.reason_codes == ()
    assert result.decision == "READY"
    assert len(result.artifacts) == 6
    assert all(len(item.sha256) == 64 for item in result.artifacts)
    assert result.fault_scenarios_passed == result.fault_scenarios_required == 6


def test_legitimate_skips_do_not_break_deterministic_ci(tmp_path):
    inputs = _complete_inputs(
        tmp_path,
        full_suite_cases=[
            _case("tests.unit.test_scan", "test_blocks"),
            _case("tests.unit.test_scan", "test_symlink", "skipped"),
        ],
    )
    result = evaluate_release_gate(inputs)
    assert result.decision == "READY"
    assert "DETERMINISTIC_CI_NOT_GREEN" not in result.readiness.reason_codes


def test_failing_suite_case_blocks_release(tmp_path):
    inputs = _complete_inputs(
        tmp_path,
        full_suite_cases=[
            _case("tests.unit.test_scan", "test_blocks"),
            _case("tests.unit.test_scan", "test_broken", "failure"),
        ],
    )
    result = evaluate_release_gate(inputs)
    assert result.decision == "NOT_READY"
    assert "DETERMINISTIC_CI_NOT_GREEN" in result.readiness.reason_codes


def test_pilot_stop_blocks_release(tmp_path):
    result = evaluate_release_gate(_complete_inputs(tmp_path, decision="STOP"))
    assert result.decision == "NOT_READY"
    assert "REPEATED_PILOT_NOT_GO" in result.readiness.reason_codes


def test_failed_operational_verifier_blocks_release(tmp_path):
    first = OPERATIONAL_SCENARIO_TESTS["bounded_retry_passed"][0]
    inputs = _complete_inputs(tmp_path, operational_outcomes={first: "failure"})
    result = evaluate_release_gate(inputs)
    assert result.decision == "NOT_READY"
    assert result.operational_scenarios["bounded_retry_passed"] is False
    assert "OPERATIONAL_SAFETY_REQUIREMENT_FAILED" in result.readiness.reason_codes


def test_skipped_clean_install_smoke_blocks_release(tmp_path):
    inputs = _complete_inputs(
        tmp_path, smoke_outcomes={CLEAN_INSTALL_SMOKE_TESTS[0]: "skipped"}
    )
    result = evaluate_release_gate(inputs)
    assert result.decision == "NOT_READY"
    assert "CLEAN_INSTALL_SMOKE_NOT_GREEN" in result.readiness.reason_codes


def test_missing_artifact_fails_closed(tmp_path):
    inputs = _complete_inputs(tmp_path)
    broken = GateInputs(
        pilot_report=tmp_path / "absent.json",
        real_world_report=inputs.real_world_report,
        operational_report=inputs.operational_report,
        assurance_report=inputs.assurance_report,
        smoke_report=inputs.smoke_report,
        full_suite_report=inputs.full_suite_report,
    )
    with pytest.raises(ReadinessGateError, match="unavailable"):
        evaluate_release_gate(broken)


def test_wrong_pilot_schema_fails_closed(tmp_path):
    inputs = _complete_inputs(tmp_path)
    inputs.pilot_report.write_text(json.dumps({"schema_version": "other"}), encoding="utf-8")
    with pytest.raises(ReadinessGateError, match="schema"):
        evaluate_release_gate(inputs)


def test_main_returns_zero_when_ready_and_one_when_blocked(tmp_path):
    ready = _complete_inputs(tmp_path / "ready")
    ready_dir = tmp_path / "ready-reports"
    assert main(_argv(ready, ready_dir)) == 0
    assert (ready_dir / "release-gate.json").is_file()
    assert (ready_dir / "release-gate.md").is_file()

    blocked = _complete_inputs(tmp_path / "blocked", decision="STOP")
    assert main(_argv(blocked)) == 1


def test_main_returns_two_on_input_error(tmp_path, capsys):
    empty = tmp_path / "empty"
    argv = [
        "--pilot-report", str(empty / "a.json"),
        "--real-world-report", str(empty / "b.json"),
        "--operational-report", str(empty / "c.xml"),
        "--assurance-report", str(empty / "d.xml"),
        "--smoke-report", str(empty / "e.xml"),
        "--full-suite-report", str(empty / "f.xml"),
    ]
    assert main(argv) == 2
    assert "input error" in capsys.readouterr().err
