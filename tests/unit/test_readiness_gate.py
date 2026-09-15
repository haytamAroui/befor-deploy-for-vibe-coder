"""Tests for the release-blocking software readiness gate.

The load-bearing property under test is the split itself: model-evaluation evidence (§1 repeated
benchmark, §3 independent real-world validation) must be *reported* and must **never** be able to
block a software release. Several tests here exist only to prove that direction holds.
"""

import ast
import json
from pathlib import Path

import pytest

from before_deploy.readiness_gate import (
    ASSURANCE_WORKFLOW_TESTS,
    CLEAN_INSTALL_SMOKE_TESTS,
    OPERATIONAL_SCENARIO_TESTS,
    REAL_WORLD_STATE_ABSENT,
    REAL_WORLD_STATE_DEFINITION_ONLY,
    REAL_WORLD_STATE_MEASURED,
    CaseOutcome,
    GateInputs,
    ReadinessGateError,
    evaluate_release_gate,
    lint_violation_count,
    main,
    parse_junit_outcomes,
    pilot_diagnostic,
    real_world_diagnostic,
    resolve_scenario,
    self_scan_verdict,
)

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


def _lint_report(path: Path, violations=()) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(list(violations)), encoding="utf-8")
    return path


def _self_scan_report(
    path: Path, *, outcome: str = "PASS", blocking=(), errors=()
) -> Path:
    payload = {
        "schema_version": 1,
        "scan": {
            "decision": {
                "outcome": outcome,
                "blocking_fingerprints": list(blocking),
                "error_control_ids": list(errors),
            }
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _distribution_dir(path: Path, *, wheel: bool = True, sdist: bool = True) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if wheel:
        (path / "before_deploy-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    if sdist:
        (path / "before_deploy-0.1.0.tar.gz").write_bytes(b"sdist")
    return path


def _pilot_report(path: Path, *, decision: str = "GO", stability: float = 1.0) -> Path:
    payload = {
        "schema_version": "before-deploy-caller-pilot-result-v1",
        "caller_pilot": {
            "decision": decision,
            "reason_codes": [] if decision == "GO" else ["FALSE_POSITIVE_TRAP_REGRESSED"],
            "exploration_required_recall_lift": 0.775,
            "false_positive_trap_rate_delta": 0.0,
            "static_sufficient_recall_delta": 0.0,
            "exploratory_variant": {"prediction_stability": stability},
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _real_world_report(path: Path, *, recall: float = 0.667) -> Path:
    payload = {
        "schema_version": "before-deploy-real-world-validation-v1",
        "real_world_validation": {
            "name": "rw",
            "decision": "PASS",
            "reason_codes": [],
            "repository_count": 3,
            "known_defects": 6,
            "detected_defects": 4,
            "recall": recall,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _corpus_definition_report(path: Path) -> Path:
    """Reproduce the payload ``real-world-validation.yml`` actually uploads."""
    payload = {
        "authority": "BENCHMARK_DIAGNOSTIC",
        "blinded": True,
        "gate_effect": "NONE",
        "independent": True,
        "known_defects": 6,
        "repositories": [
            {"repository_id": f"RW-{index}", "known_defects": 2, "reviewed_file_count": 4}
            for index in range(3)
        ],
        "reviewed_file_count": 12,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _healthy_inputs(
    tmp_path: Path,
    *,
    self_scan_outcome: str = "PASS",
    self_scan_blocking=(),
    lint_violations=(),
    wheel: bool = True,
    sdist: bool = True,
    operational_outcomes=None,
    assurance_outcomes=None,
    smoke_outcomes=None,
    full_suite_cases=None,
    pilot: Path | None = None,
    real_world: Path | None = None,
) -> GateInputs:
    full_cases = (
        full_suite_cases
        if full_suite_cases is not None
        else [_case("tests.unit.test_scan", "test_blocks")]
    )
    return GateInputs(
        full_suite_report=_write_junit(tmp_path / "full.xml", full_cases),
        lint_report=_lint_report(tmp_path / "lint.json", lint_violations),
        self_scan_report=_self_scan_report(
            tmp_path / "self-scan.json",
            outcome=self_scan_outcome,
            blocking=self_scan_blocking,
        ),
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
        distribution_dir=_distribution_dir(tmp_path / "dist", wheel=wheel, sdist=sdist),
        pilot_report=pilot,
        real_world_report=real_world,
    )


def _argv(inputs: GateInputs, output_dir: Path | None = None) -> list[str]:
    argv = [
        "--full-suite-report", str(inputs.full_suite_report),
        "--lint-report", str(inputs.lint_report),
        "--self-scan-report", str(inputs.self_scan_report),
        "--operational-report", str(inputs.operational_report),
        "--assurance-report", str(inputs.assurance_report),
        "--smoke-report", str(inputs.smoke_report),
        "--distribution-dir", str(inputs.distribution_dir),
    ]
    if inputs.pilot_report is not None:
        argv += ["--pilot-report", str(inputs.pilot_report)]
    if inputs.real_world_report is not None:
        argv += ["--real-world-report", str(inputs.real_world_report)]
    if output_dir is not None:
        argv += ["--output-dir", str(output_dir)]
    return argv


# --------------------------------------------------------------------------------------
# The split: model-evaluation evidence is reported and never blocks.
# --------------------------------------------------------------------------------------


def test_healthy_software_is_ready(tmp_path):
    result = evaluate_release_gate(_healthy_inputs(tmp_path))
    assert result.decision == "READY"
    assert result.software.reason_codes == ()
    assert all(result.software.criteria.values())


def test_failed_benchmark_does_not_block_a_healthy_release(tmp_path):
    """A recorded `STOP` is model-evaluation evidence: it must not stop a software release."""
    inputs = _healthy_inputs(tmp_path, pilot=_pilot_report(tmp_path / "pilot.json", decision="STOP"))
    result = evaluate_release_gate(inputs)
    assert result.decision == "READY"
    assert result.model_evaluation.pilot_decision == "STOP"
    # ...and it is still reported, so nobody can mistake silence for a pass.
    assert result.model_evaluation.pilot_reason_codes == ("FALSE_POSITIVE_TRAP_REGRESSED",)
    assert main(_argv(inputs)) == 0


def test_zero_recall_real_world_evidence_does_not_block_a_healthy_release(tmp_path):
    inputs = _healthy_inputs(
        tmp_path,
        pilot=_pilot_report(tmp_path / "pilot.json"),
        real_world=_corpus_definition_report(tmp_path / "rw.json"),
    )
    result = evaluate_release_gate(inputs)
    assert result.decision == "READY"
    assert result.model_evaluation.real_world_state == REAL_WORLD_STATE_DEFINITION_ONLY
    assert result.model_evaluation.real_world_recall is None


def test_absent_model_evaluation_evidence_does_not_block_and_is_reported(tmp_path):
    result = evaluate_release_gate(_healthy_inputs(tmp_path))
    assert result.decision == "READY"
    assert result.model_evaluation.pilot_supplied is False
    assert result.model_evaluation.real_world_state == REAL_WORLD_STATE_ABSENT
    assert result.model_evaluation.blocking is False


def test_malformed_model_evaluation_evidence_cannot_block_a_release(tmp_path):
    """A diagnostic must never block, so an unreadable one degrades to 'unsupplied'."""
    broken = tmp_path / "pilot.json"
    broken.write_text("{not json", encoding="utf-8")
    result = evaluate_release_gate(_healthy_inputs(tmp_path, pilot=broken))
    assert result.decision == "READY"
    assert result.model_evaluation.pilot_supplied is False


def test_malformed_real_world_evidence_cannot_block_a_release(tmp_path):
    broken = tmp_path / "rw.json"
    broken.write_text("[1, 2, 3]", encoding="utf-8")
    result = evaluate_release_gate(_healthy_inputs(tmp_path, real_world=broken))
    assert result.decision == "READY"
    assert result.model_evaluation.real_world_state == REAL_WORLD_STATE_ABSENT


def test_model_evaluation_diagnostics_are_reported_in_full(tmp_path):
    inputs = _healthy_inputs(
        tmp_path,
        pilot=_pilot_report(tmp_path / "pilot.json"),
        real_world=_real_world_report(tmp_path / "rw.json"),
    )
    result = evaluate_release_gate(inputs)
    assert result.decision == "READY"
    diagnostic = result.model_evaluation
    assert diagnostic.pilot_decision == "GO"
    assert diagnostic.exploration_required_recall_lift == pytest.approx(0.775)
    assert diagnostic.false_positive_trap_rate_delta == pytest.approx(0.0)
    assert diagnostic.static_sufficient_recall_delta == pytest.approx(0.0)
    assert diagnostic.exploratory_prediction_stability == pytest.approx(1.0)
    assert diagnostic.real_world_state == REAL_WORLD_STATE_MEASURED
    assert diagnostic.real_world_recall == pytest.approx(0.667)
    assert diagnostic.real_world_decision == "PASS"


def test_diagnostic_helpers_report_shapes_without_raising():
    assert pilot_diagnostic(None)["pilot_supplied"] is False
    assert real_world_diagnostic(None)["real_world_state"] == REAL_WORLD_STATE_ABSENT


# --------------------------------------------------------------------------------------
# Software criteria do block.
# --------------------------------------------------------------------------------------


def test_lint_violations_block_the_release(tmp_path):
    inputs = _healthy_inputs(tmp_path, lint_violations=[{"code": "F401"}])
    assert evaluate_release_gate(inputs).software.reason_codes == ("LINT_NOT_CLEAN",)


def test_missing_lint_report_is_an_input_error(tmp_path):
    inputs = _healthy_inputs(tmp_path)
    inputs.lint_report.unlink()
    with pytest.raises(ReadinessGateError, match="lint-report"):
        evaluate_release_gate(inputs)


def test_lint_report_that_is_not_an_array_is_an_input_error(tmp_path):
    inputs = _healthy_inputs(tmp_path)
    inputs.lint_report.write_text('{"violations": 0}', encoding="utf-8")
    with pytest.raises(ReadinessGateError, match="ruff"):
        evaluate_release_gate(inputs)


def test_lint_violation_count_reads_ruff_json(tmp_path):
    assert lint_violation_count(_lint_report(tmp_path / "clean.json")) == 0
    assert lint_violation_count(_lint_report(tmp_path / "dirty.json", [{"code": "E1"}])) == 1


@pytest.mark.parametrize("outcome", ["NOT_EVALUATED", "BLOCK", "WAIVER_REQUIRED", "ERROR"])
def test_non_passing_self_scan_blocks_the_release(tmp_path, outcome):
    inputs = _healthy_inputs(tmp_path, self_scan_outcome=outcome)
    assert "SELF_SCAN_NOT_PASS" in evaluate_release_gate(inputs).software.reason_codes


def test_self_scan_blocking_findings_block_the_release(tmp_path):
    inputs = _healthy_inputs(tmp_path, self_scan_blocking=["fp-1"])
    assert "SELF_SCAN_NOT_PASS" in evaluate_release_gate(inputs).software.reason_codes


def test_self_scan_verdict_is_read_from_the_report(tmp_path):
    path = _self_scan_report(tmp_path / "r.json", outcome="BLOCK", blocking=["a", "b"])
    assert self_scan_verdict(path) == ("BLOCK", 2, 0)


def test_self_scan_report_without_a_decision_is_an_input_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"scan": {}}), encoding="utf-8")
    with pytest.raises(ReadinessGateError, match="decision"):
        self_scan_verdict(path)


def test_missing_distribution_blocks_the_release(tmp_path):
    inputs = _healthy_inputs(tmp_path, sdist=False)
    assert "DISTRIBUTION_NOT_BUILT" in evaluate_release_gate(inputs).software.reason_codes


def test_absent_distribution_directory_is_an_input_error(tmp_path):
    inputs = _healthy_inputs(tmp_path)
    for item in inputs.distribution_dir.iterdir():
        item.unlink()
    inputs.distribution_dir.rmdir()
    with pytest.raises(ReadinessGateError, match="distribution directory"):
        evaluate_release_gate(inputs)


def test_built_distributions_are_digested_as_evidence(tmp_path):
    inputs = _healthy_inputs(tmp_path)
    result = evaluate_release_gate(inputs)
    names = {item.name for item in result.artifacts}
    assert "before_deploy-0.1.0-py3-none-any.whl" in names
    assert "before_deploy-0.1.0.tar.gz" in names


def test_full_suite_failure_blocks_the_release(tmp_path):
    cases = [_case("tests.unit.test_scan", "test_blocks", "failure")]
    inputs = _healthy_inputs(tmp_path, full_suite_cases=cases)
    assert "DETERMINISTIC_CI_NOT_GREEN" in evaluate_release_gate(inputs).software.reason_codes


def test_full_suite_skips_are_tolerated(tmp_path):
    """Capability-probed tests (symlink support) legitimately skip; that is not a failure."""
    cases = [
        _case("tests.unit.test_scan", "test_blocks"),
        _case("tests.unit.test_scan", "test_symlink", "skipped"),
    ]
    inputs = _healthy_inputs(tmp_path, full_suite_cases=cases)
    assert evaluate_release_gate(inputs).decision == "READY"


def test_failed_operational_scenario_blocks_the_release(tmp_path):
    failed = ALL_OPERATIONAL_VERIFIERS[0]
    inputs = _healthy_inputs(tmp_path, operational_outcomes={failed: "failure"})
    result = evaluate_release_gate(inputs)
    assert "OPERATIONAL_FAULT_COVERAGE_INCOMPLETE" in result.software.reason_codes
    assert result.fault_scenarios_passed == result.fault_scenarios_required - 1


def test_skipped_operational_verifier_is_not_a_pass(tmp_path):
    skipped = ALL_OPERATIONAL_VERIFIERS[0]
    inputs = _healthy_inputs(tmp_path, operational_outcomes={skipped: "skipped"})
    assert "OPERATIONAL_FAULT_COVERAGE_INCOMPLETE" in evaluate_release_gate(inputs).software.reason_codes


def test_failed_assurance_workflow_blocks_the_release(tmp_path):
    inputs = _healthy_inputs(tmp_path, assurance_outcomes={ASSURANCE_WORKFLOW_TESTS[0]: "failure"})
    assert "FULL_ASSURANCE_WORKFLOW_NOT_PROVEN" in evaluate_release_gate(inputs).software.reason_codes


def test_skipped_clean_install_smoke_blocks_the_release(tmp_path):
    inputs = _healthy_inputs(tmp_path, smoke_outcomes={CLEAN_INSTALL_SMOKE_TESTS[0]: "skipped"})
    assert "CLEAN_INSTALL_SMOKE_NOT_GREEN" in evaluate_release_gate(inputs).software.reason_codes


def test_missing_blocking_artifact_is_an_input_error(tmp_path):
    inputs = _healthy_inputs(tmp_path)
    inputs.operational_report.unlink()
    with pytest.raises(ReadinessGateError, match="unavailable"):
        evaluate_release_gate(inputs)


def test_main_returns_zero_when_ready(tmp_path):
    inputs = _healthy_inputs(tmp_path)
    output_dir = tmp_path / "reports"
    assert main(_argv(inputs, output_dir)) == 0
    assert (output_dir / "release-gate.json").is_file()
    assert (output_dir / "release-gate.md").is_file()


def test_main_returns_one_when_blocked(tmp_path, capsys):
    inputs = _healthy_inputs(tmp_path, lint_violations=[{"code": "F401"}])
    assert main(_argv(inputs)) == 1
    assert "release blocked" in capsys.readouterr().err


def test_main_returns_two_on_input_error(tmp_path, capsys):
    empty = tmp_path / "empty"
    argv = [
        "--full-suite-report", str(empty / "a.xml"),
        "--lint-report", str(empty / "b.json"),
        "--self-scan-report", str(empty / "c.json"),
        "--operational-report", str(empty / "d.xml"),
        "--assurance-report", str(empty / "e.xml"),
        "--smoke-report", str(empty / "f.xml"),
        "--distribution-dir", str(empty / "dist"),
    ]
    assert main(argv) == 2
    assert "input error" in capsys.readouterr().err


def test_rendered_report_separates_software_from_model_evaluation(tmp_path):
    inputs = _healthy_inputs(
        tmp_path,
        pilot=_pilot_report(tmp_path / "pilot.json", decision="STOP"),
        real_world=_corpus_definition_report(tmp_path / "rw.json"),
    )
    output_dir = tmp_path / "reports"
    assert main(_argv(inputs, output_dir)) == 0
    payload = json.loads((output_dir / "release-gate.json").read_text(encoding="utf-8"))
    gate = payload["release_gate"]
    assert gate["decision"] == "READY"
    assert gate["software_reason_codes"] == []
    # The recorded STOP is visible, and explicitly non-blocking.
    assert gate["model_evaluation"]["pilot_decision"] == "STOP"
    assert gate["model_evaluation"]["blocking"] is False
    assert gate["model_evaluation"]["real_world_state"] == REAL_WORLD_STATE_DEFINITION_ONLY
    markdown = (output_dir / "release-gate.md").read_text(encoding="utf-8")
    assert "does not block this release" in markdown


# --------------------------------------------------------------------------------------
# Frozen verifier map integrity.
# --------------------------------------------------------------------------------------


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


def test_parametrized_verifier_passes_only_when_every_parameterization_passes():
    """A parametrized verifier is matched by base node id; all parameterizations must pass.

    `malformed_output_safe` is parametrized in the real suite. An exact-node-id lookup silently
    turned it into an input error, which would have failed the very first release run.
    """
    declared = ["tests/unit/test_x.py::test_y"]
    all_passed = (
        CaseOutcome("tests.unit.test_x::test_y[a]", "passed"),
        CaseOutcome("tests.unit.test_x::test_y[b]", "passed"),
    )
    assert resolve_scenario(declared, all_passed, scenario="demo") is True

    for bad in ("failed", "skipped"):
        mixed = (
            CaseOutcome("tests.unit.test_x::test_y[a]", "passed"),
            CaseOutcome("tests.unit.test_x::test_y[b]", bad),
        )
        assert resolve_scenario(declared, mixed, scenario="demo") is False


def test_parametrized_verifier_absent_entirely_is_still_an_input_error():
    outcomes = (CaseOutcome("tests.unit.test_x::test_other[a]", "passed"),)
    with pytest.raises(ReadinessGateError, match="no result"):
        resolve_scenario(["tests/unit/test_x.py::test_y"], outcomes, scenario="demo")


def test_real_operational_verifiers_unique_base_ids_beyond_parametrization():
    """Guards against a parameterization that a base-id match would collapse incorrectly."""
    bases = [declared.split("[", 1)[0] for declared in ALL_OPERATIONAL_VERIFIERS]
    assert len(bases) == len(set(bases)), "two declared verifiers share a base node id"


def test_junit_parser_treats_only_clean_cases_as_passed(tmp_path):
    path = _write_junit(
        tmp_path / "mixed.xml",
        [
            _case("tests.unit.test_a", "ok"),
            _case("tests.unit.test_a", "boom", "failure"),
            _case("tests.unit.test_a", "skip", "skipped"),
        ],
    )
    statuses = {outcome.node_id: outcome.status for outcome in parse_junit_outcomes(path)}
    assert statuses["tests.unit.test_a::ok"] == "passed"
    assert statuses["tests.unit.test_a::boom"] == "failed"
    assert statuses["tests.unit.test_a::skip"] == "skipped"


# --------------------------------------------------------------------------------------
# Workflow drift guard: the release path must stay decoupled and keep passing real evidence.
# --------------------------------------------------------------------------------------


def test_release_workflow_passes_every_required_gate_input_and_no_benchmark_gate():
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    for flag in (
        "--full-suite-report",
        "--lint-report",
        "--self-scan-report",
        "--operational-report",
        "--assurance-report",
        "--smoke-report",
        "--distribution-dir",
    ):
        assert flag in release, f"release.yml no longer supplies {flag}"

    # Decoupling: the release path must consume no cross-run artifact and enforce no ancestry or
    # freshness rule, since those existed only to bind the release to benchmark evidence.
    assert "download-artifact" not in release
    assert "run-id:" not in release
    assert "READINESS_BRANCH" not in release
    assert "merge-base --is-ancestor" not in release
    # ...and it must still run the self-scan it now gates on.
    assert "strict-ci-policy.yaml" in release
    assert "before-deploy-readiness-gate" in release


def test_benchmark_workflows_remain_available_as_standalone_evaluations():
    for name in ("production-readiness-luna.yml", "real-world-validation.yml"):
        body = Path(f".github/workflows/{name}").read_text(encoding="utf-8")
        assert "workflow_dispatch" in body, f"{name} is no longer independently runnable"


def test_production_readiness_evaluator_is_retained_as_a_diagnostic_module():
    """The frozen criteria stay implemented; only their gate effect on releases is removed."""
    source = Path("src/before_deploy/production_readiness.py").read_text(encoding="utf-8")
    assert "PRODUCTION_READINESS_GATE_EFFECT = \"NONE\"" in source
