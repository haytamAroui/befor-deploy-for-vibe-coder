"""Release-blocking readiness gate for Preflight itself.

``before_deploy.production_readiness`` evaluates readiness but declares
``gate_effect = "NONE"``: it reports, it does not stop anything. This module is the part
that is allowed to stop a release.

Design rules:

* Every field of ``ProductionReadinessEvidence`` is derived from an artifact produced by
  CI. No boolean is accepted from the command line, so a hand-written "everything passed"
  cannot satisfy the gate.
* The operational and CI facts are derived from JUnit reports against a frozen scenario
  map. A scenario whose verifier is absent from the report is an *input error*, not a
  silent pass; a scenario whose verifier failed or was skipped is a failure.
* Missing, unreadable, or schema-invalid input fails closed.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from hashlib import sha256
from json import dumps, loads
from pathlib import Path
from typing import Any, Mapping, Sequence
from xml.etree import ElementTree

from .caller_pilot import CALLER_PILOT_RESULT_SCHEMA
from .production_readiness import (
    ProductionReadinessAssessment,
    ProductionReadinessEvidence,
    evaluate_production_readiness,
    render_production_readiness_markdown,
)
from .real_world_validation import (
    REAL_WORLD_VALIDATION_SCHEMA,
    RealWorldValidationResult,
    real_world_readiness_evidence,
)

READINESS_GATE_SCHEMA = "before-deploy-readiness-gate-v1"
READINESS_GATE_AUTHORITY = "RELEASE_GATE"
READINESS_GATE_EFFECT = "BLOCKS_RELEASE"

#: Verifiers for the operational safety flags. Each flag is true only when every declared
#: verifier is present in the operational JUnit report and passed. Parametrized verifiers are
#: matched by their base node id and must all pass.
OPERATIONAL_SCENARIO_TESTS: Mapping[str, tuple[str, ...]] = {
    "bounded_retry_passed": (
        "tests/unit/test_production_openai_bridge.py"
        "::test_transient_http_errors_retry_with_bounded_backoff",
        "tests/unit/test_production_openai_bridge.py"
        "::test_transport_failure_retries_only_to_attempt_limit",
    ),
    "malformed_output_safe": (
        "tests/unit/test_caller_bridge_failure_modes.py"
        "::test_bridge_fails_closed_on_malformed_api_payload",
    ),
    "missing_credentials_safe": (
        "tests/unit/test_caller_bridge_failure_modes.py"
        "::test_bridge_requires_api_key_and_makes_no_network_request_when_absent",
        "tests/unit/test_production_openai_bridge.py::test_authentication_error_is_not_retried",
    ),
    "timeout_safe": (
        "tests/unit/test_external_adapters.py::test_external_tool_timeout_is_an_explicit_error",
        "tests/unit/test_trivy_config_adapter.py"
        "::test_trivy_config_fails_closed_for_version_mismatch_malformed_report_and_timeout",
    ),
    "cost_budget_enforced": (
        "tests/unit/test_production_openai_bridge.py"
        "::test_cumulative_budget_fails_closed_and_does_not_commit_overage",
        "tests/unit/test_production_openai_bridge.py"
        "::test_precheck_stops_before_next_request_when_budget_is_at_limit",
    ),
    "advisory_authority_isolated": (
        "tests/unit/test_evidence_graph.py::test_only_policy_decision_node_has_release_authority",
        "tests/unit/test_advisory_provider.py"
        "::test_provider_runtime_forces_advisory_authority_and_attests_execution",
    ),
}

#: Verifiers for the end-to-end assurance workflow.
ASSURANCE_WORKFLOW_TESTS: tuple[str, ...] = (
    "tests/integration/test_scan_fixtures.py"
    "::test_python_observability_policy_blocks_print_and_passes_safe_fixture",
    "tests/integration/test_nextjs_fixture_scans.py"
    "::test_vulnerable_nextjs_fixture_blocks_on_new_nextjs_controls",
    "tests/integration/test_nextjs_fixture_scans.py"
    "::test_secure_nextjs_fixture_passes_and_reports_nextjs_profile",
)

#: Verifiers for the clean-install smoke. These skip unless an isolated install exists, so a
#: skipped run is correctly reported as absent evidence.
CLEAN_INSTALL_SMOKE_TESTS: tuple[str, ...] = (
    "tests/integration/test_clean_install_smoke.py"
    "::test_distribution_declares_every_console_entry_point",
    "tests/integration/test_clean_install_smoke.py"
    "::test_installed_cli_renders_help_without_importing_from_the_source_tree",
)

#: JUnit child tags that mean a case did not pass, and which of them is a genuine failure.
_SKIPPED_TAG = "skipped"
_FAILED_TAGS = frozenset({"failure", "error"})
_STATUS_PASSED = "passed"
_STATUS_FAILED = "failed"
_STATUS_SKIPPED = "skipped"


class ReadinessGateError(RuntimeError):
    """Raised when gate inputs are missing, unreadable, or schema-invalid."""


@dataclass(frozen=True)
class CaseOutcome:
    """A JUnit test case result.

    ``status`` is one of ``passed``, ``failed``, or ``skipped``. Skips are tracked separately
    from failures because the deterministic suite legitimately skips capability-probed tests
    (symlink support), while an operational scenario verifier must never be satisfied by a skip.
    """

    node_id: str
    status: str

    @property
    def passed(self) -> bool:
        return self.status == _STATUS_PASSED


@dataclass(frozen=True)
class ArtifactDigest:
    name: str
    sha256: str
    relative_path: str


@dataclass(frozen=True)
class GateInputs:
    """Artifact paths supplied by the release workflow."""

    pilot_report: Path
    real_world_report: Path
    operational_report: Path
    assurance_report: Path
    smoke_report: Path
    full_suite_report: Path


@dataclass(frozen=True)
class ReleaseGateResult:
    readiness: ProductionReadinessAssessment
    artifacts: tuple[ArtifactDigest, ...]
    operational_scenarios: Mapping[str, bool]
    fault_scenarios_required: int
    fault_scenarios_passed: int
    schema_version: str = READINESS_GATE_SCHEMA
    authority: str = READINESS_GATE_AUTHORITY
    gate_effect: str = READINESS_GATE_EFFECT

    @property
    def decision(self) -> str:
        return self.readiness.decision


def _digest(name: str, path: Path) -> ArtifactDigest:
    if not path.is_file():
        raise ReadinessGateError(f"required readiness artifact {name} is unavailable: {path}")
    return ArtifactDigest(
        name=name,
        sha256=sha256(path.read_bytes()).hexdigest(),
        relative_path=path.name,
    )


def _load_json(name: str, path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        raise ReadinessGateError(f"required readiness artifact {name} is unavailable: {path}")
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReadinessGateError(
            f"readiness artifact {name} is not valid JSON: {path}"
        ) from error
    if not isinstance(payload, Mapping):
        raise ReadinessGateError(f"readiness artifact {name} must be a JSON object: {path}")
    return payload


def _field(source: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in source:
        raise ReadinessGateError(f"{where} is missing required field {key!r}")
    return source[key]


def _dotted_node_id(node_id: str) -> tuple[str, str]:
    """Convert ``path/to/test_mod.py::test_name`` into pytest's JUnit classname form."""
    path, separator, test_name = node_id.partition("::")
    if not separator or not path or not test_name:
        raise ReadinessGateError(f"operational verifier id {node_id!r} is not a pytest node id")
    module = path[:-3] if path.endswith(".py") else path
    return module.replace("\\", ".").replace("/", "."), test_name


def parse_junit_outcomes(path: Path) -> tuple[CaseOutcome, ...]:
    """Return a :class:`CaseOutcome` for every case in a JUnit XML report.

    ``node_id`` is reported in dotted pytest form, e.g. ``tests.unit.test_scan::test_blocks``.
    """
    if not path.is_file():
        raise ReadinessGateError(f"required test report is unavailable: {path}")
    try:
        root = ElementTree.fromstring(path.read_bytes())
    except ElementTree.ParseError as error:
        raise ReadinessGateError(f"test report is not valid JUnit XML: {path}") from error
    outcomes: list[CaseOutcome] = []
    for case in root.iter("testcase"):
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        if not name:
            continue
        tags = {child.tag for child in case}
        if tags & _FAILED_TAGS:
            status = _STATUS_FAILED
        elif _SKIPPED_TAG in tags:
            status = _STATUS_SKIPPED
        else:
            status = _STATUS_PASSED
        outcomes.append(CaseOutcome(f"{classname}::{name}", status))
    return tuple(outcomes)


def resolve_scenario(
    declared: Sequence[str],
    outcomes: Sequence[CaseOutcome],
    *,
    scenario: str,
) -> bool:
    """Return whether every declared verifier is present and passed.

    A declared verifier with no matching case in the report means the scenario was never
    exercised, which is an input error rather than a pass.
    """
    passed = True
    for node_id in declared:
        classname, test_name = _dotted_node_id(node_id)
        matches = [
            outcome
            for outcome in outcomes
            if outcome.node_id.split("::", 1)[0].endswith(classname)
            and (
                outcome.node_id.split("::", 1)[1] == test_name
                or outcome.node_id.split("::", 1)[1].startswith(f"{test_name}[")
            )
        ]
        if not matches:
            raise ReadinessGateError(
                f"operational scenario {scenario!r} has no result for {node_id!r}; "
                "the verifier was not collected or was renamed"
            )
        if not all(item.passed for item in matches):
            passed = False
    return passed


def pilot_evidence_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the repeated-benchmark evidence fields from a caller-pilot report."""
    if payload.get("schema_version") != CALLER_PILOT_RESULT_SCHEMA:
        raise ReadinessGateError(
            "caller pilot report does not declare schema "
            f"{CALLER_PILOT_RESULT_SCHEMA!r}"
        )
    report = _field(payload, "caller_pilot", "caller pilot report")
    if not isinstance(report, Mapping):
        raise ReadinessGateError("caller pilot report payload must be an object")
    static = _field(report, "static_variant", "caller pilot report")
    exploratory = _field(report, "exploratory_variant", "caller pilot report")
    if not isinstance(static, Mapping) or not isinstance(exploratory, Mapping):
        raise ReadinessGateError("caller pilot variants must be objects")
    return {
        "pilot_decision": _field(report, "decision", "caller pilot report"),
        "static_run_count": _field(static, "run_count", "caller pilot static variant"),
        "exploratory_run_count": _field(
            exploratory, "run_count", "caller pilot exploratory variant"
        ),
        "exploration_required_recall_lift": _field(
            report, "exploration_required_recall_lift", "caller pilot report"
        ),
        "exploration_attributable_tp": _field(
            exploratory, "exploration_attributable_tp", "caller pilot exploratory variant"
        ),
        "exploration_attributable_fp": _field(
            exploratory, "exploration_attributable_fp", "caller pilot exploratory variant"
        ),
        "false_positive_trap_rate_delta": _field(
            report, "false_positive_trap_rate_delta", "caller pilot report"
        ),
        "static_sufficient_recall_delta": _field(
            report, "static_sufficient_recall_delta", "caller pilot report"
        ),
        "exploratory_supported_claim_rate": _field(
            exploratory, "supported_claim_rate", "caller pilot exploratory variant"
        ),
        "exploratory_citation_correct_rate": _field(
            exploratory, "citation_correct_rate", "caller pilot exploratory variant"
        ),
        "exploratory_prediction_claim_stability": _field(
            exploratory, "prediction_stability", "caller pilot exploratory variant"
        ),
        "exploratory_exact_prediction_stability": _field(
            exploratory, "exact_prediction_stability", "caller pilot exploratory variant"
        ),
        "exploratory_mean_latency_ms": _field(
            exploratory, "mean_latency_ms", "caller pilot exploratory variant"
        ),
        "exploratory_mean_cost_microusd": _field(
            exploratory, "mean_cost_microusd", "caller pilot exploratory variant"
        ),
    }


def real_world_evidence_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the independent-validation evidence fields from a §3 report."""
    if payload.get("schema_version") != REAL_WORLD_VALIDATION_SCHEMA:
        raise ReadinessGateError(
            "real-world report does not declare schema "
            f"{REAL_WORLD_VALIDATION_SCHEMA!r}"
        )
    report = _field(payload, "real_world_validation", "real-world report")
    if not isinstance(report, Mapping):
        raise ReadinessGateError("real-world report payload must be an object")
    where = "real-world report"
    reason_codes = _field(report, "reason_codes", where)
    if not isinstance(reason_codes, list):
        raise ReadinessGateError("real-world reason_codes must be a list")
    result = RealWorldValidationResult(
        name=str(_field(report, "name", where)),
        decision=str(_field(report, "decision", where)),
        reason_codes=tuple(str(item) for item in reason_codes),
        repository_count=int(_field(report, "repository_count", where)),
        known_defects=int(_field(report, "known_defects", where)),
        detected_defects=int(_field(report, "detected_defects", where)),
        recall=float(_field(report, "recall", where)),
        exploration_attributable_tp=int(_field(report, "exploration_attributable_tp", where)),
        exploration_attributable_fp=int(_field(report, "exploration_attributable_fp", where)),
        static_false_positive_rate=float(_field(report, "static_false_positive_rate", where)),
        exploratory_false_positive_rate=float(
            _field(report, "exploratory_false_positive_rate", where)
        ),
        blinded=bool(_field(report, "blinded", where)),
        independent=bool(_field(report, "independent", where)),
    )
    return real_world_readiness_evidence(result)


def evaluate_release_gate(inputs: GateInputs) -> ReleaseGateResult:
    """Assemble readiness evidence from CI artifacts and evaluate the frozen criteria."""
    artifacts = (
        _digest("caller-pilot.json", inputs.pilot_report),
        _digest("real-world-validation.json", inputs.real_world_report),
        _digest("operational-junit.xml", inputs.operational_report),
        _digest("assurance-junit.xml", inputs.assurance_report),
        _digest("smoke-junit.xml", inputs.smoke_report),
        _digest("full-suite-junit.xml", inputs.full_suite_report),
    )

    pilot = pilot_evidence_fields(_load_json("caller-pilot.json", inputs.pilot_report))
    real_world = real_world_evidence_fields(
        _load_json("real-world-validation.json", inputs.real_world_report)
    )

    operational_outcomes = parse_junit_outcomes(inputs.operational_report)
    scenarios = {
        flag: resolve_scenario(declared, operational_outcomes, scenario=flag)
        for flag, declared in OPERATIONAL_SCENARIO_TESTS.items()
    }

    assurance_outcomes = parse_junit_outcomes(inputs.assurance_report)
    assurance_passed = resolve_scenario(
        ASSURANCE_WORKFLOW_TESTS, assurance_outcomes, scenario="assurance_workflow_passed"
    )

    smoke_outcomes = parse_junit_outcomes(inputs.smoke_report)
    smoke_passed = resolve_scenario(
        CLEAN_INSTALL_SMOKE_TESTS, smoke_outcomes, scenario="clean_install_smoke_passed"
    )

    full_outcomes = parse_junit_outcomes(inputs.full_suite_report)
    if not full_outcomes:
        raise ReadinessGateError("full-suite JUnit report contains no test cases")
    # Skips are tolerated here: the deterministic suite legitimately skips capability-probed
    # tests. Only genuine failures and errors make deterministic CI not green.
    deterministic_ci_passed = not any(
        outcome.status == _STATUS_FAILED for outcome in full_outcomes
    )

    evidence = ProductionReadinessEvidence(
        **pilot,
        fault_scenarios_required=len(OPERATIONAL_SCENARIO_TESTS),
        fault_scenarios_passed=sum(1 for value in scenarios.values() if value),
        **scenarios,
        **real_world,
        assurance_workflow_passed=assurance_passed,
        deterministic_ci_passed=deterministic_ci_passed,
        clean_install_smoke_passed=smoke_passed,
        retained_evidence_digest_count=len(artifacts),
    )
    passed_scenarios = sum(1 for value in scenarios.values() if value)
    return ReleaseGateResult(
        readiness=evaluate_production_readiness(evidence),
        artifacts=artifacts,
        operational_scenarios=scenarios,
        fault_scenarios_required=len(OPERATIONAL_SCENARIO_TESTS),
        fault_scenarios_passed=passed_scenarios,
    )


def render_release_gate_json(result: ReleaseGateResult) -> str:
    payload = {
        "schema_version": result.schema_version,
        "release_gate": {
            "authority": result.authority,
            "decision": result.decision,
            "fault_scenarios_passed": result.fault_scenarios_passed,
            "fault_scenarios_required": result.fault_scenarios_required,
            "gate_effect": result.gate_effect,
            "operational_scenarios": dict(sorted(result.operational_scenarios.items())),
            "reason_codes": list(result.readiness.reason_codes),
            "retained_artifacts": [
                {
                    "name": item.name,
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                }
                for item in result.artifacts
            ],
        },
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_release_gate_markdown(result: ReleaseGateResult) -> str:
    lines = [
        "# Preflight Release Readiness Gate",
        "",
        f"- Decision: **{result.decision}**",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        (
            "- Operational scenarios: "
            f"**{result.fault_scenarios_passed} / {result.fault_scenarios_required}**"
        ),
        f"- Retained evidence artifacts: **{len(result.artifacts)}**",
        "",
        "## Operational scenarios",
        "",
    ]
    for name, passed in sorted(result.operational_scenarios.items()):
        lines.append(f"- `{name}`: {'passed' if passed else 'FAILED'}")
    lines.extend(["", "## Retained evidence", ""])
    for item in result.artifacts:
        lines.append(f"- `{item.name}` sha256 `{item.sha256}`")
    lines.extend(
        [
            "",
            "## Readiness result",
            "",
            render_production_readiness_markdown(result.readiness).rstrip(),
            "",
            "> A pass means the frozen production-readiness criteria were satisfied by CI-produced",
            "> evidence. It does not grant AI findings release authority.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy-readiness-gate",
        description=(
            "Fail closed unless the frozen production-readiness criteria are satisfied by "
            "CI-produced artifacts."
        ),
    )
    parser.add_argument("--pilot-report", type=Path, required=True)
    parser.add_argument("--real-world-report", type=Path, required=True)
    parser.add_argument("--operational-report", type=Path, required=True)
    parser.add_argument("--assurance-report", type=Path, required=True)
    parser.add_argument("--smoke-report", type=Path, required=True)
    parser.add_argument("--full-suite-report", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    arguments = parser.parse_args(argv)

    inputs = GateInputs(
        pilot_report=arguments.pilot_report,
        real_world_report=arguments.real_world_report,
        operational_report=arguments.operational_report,
        assurance_report=arguments.assurance_report,
        smoke_report=arguments.smoke_report,
        full_suite_report=arguments.full_suite_report,
    )
    try:
        result = evaluate_release_gate(inputs)
    except ReadinessGateError as error:
        print(f"readiness gate input error: {error}", file=sys.stderr)
        return 2

    json_report = render_release_gate_json(result)
    markdown_report = render_release_gate_markdown(result)
    if arguments.output_dir is not None:
        arguments.output_dir.mkdir(parents=True, exist_ok=True)
        (arguments.output_dir / "release-gate.json").write_text(
            json_report, encoding="utf-8"
        )
        (arguments.output_dir / "release-gate.md").write_text(
            markdown_report, encoding="utf-8"
        )
    print(markdown_report, end="")
    if result.decision != "READY":
        print(
            "release blocked: " + ", ".join(result.readiness.reason_codes),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ArtifactDigest",
    "GateInputs",
    "CaseOutcome",
    "ReadinessGateError",
    "ReleaseGateResult",
    "evaluate_release_gate",
    "main",
    "parse_junit_outcomes",
    "pilot_evidence_fields",
    "real_world_evidence_fields",
    "render_release_gate_json",
    "render_release_gate_markdown",
    "resolve_scenario",
]
