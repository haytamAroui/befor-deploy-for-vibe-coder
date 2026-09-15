"""Release-blocking gate for the software Preflight actually ships.

``before_deploy.production_readiness`` evaluates the frozen maturity criteria in
``docs/PRODUCTION_READINESS_CRITERIA.md``. Those criteria mix two different claims, so this
module evaluates only the ones the release artifact can be held to:

* **Software release readiness (blocking)** — the deterministic engine, policy gate, CLI, MCP
  server, and packaging are healthy: criteria §2 (operational fault tolerance), §4 (full
  assurance workflow), and §5 (release engineering).
* **Model evaluation (non-blocking)** — criteria §1 (repeated blinded benchmark) and §3
  (independent real-world validation) measure an external model's inter-procedural recall. That
  is a research diagnostic with a documented ``gate_effect = NONE``, so it is *reported* here and
  never decides whether this software may be released.

Holding a release hostage to live third-party model performance coupled the artifact to an
external API's availability, pricing, and model churn. ``production_readiness.py`` and the
``production-readiness-luna`` / ``real-world-validation`` workflows remain as the Evaluation Lab.

Design rules (unchanged from the original gate):

* Every field is derived from an artifact built by CI. No boolean is accepted from the command
  line, so a hand-written "everything passed" cannot satisfy the gate.
* The operational and CI facts are derived from JUnit reports against a frozen scenario map. A
  scenario whose verifier is absent from the report is an *input error*, not a silent pass; a
  scenario whose verifier failed or was skipped is a failure.
* Missing, unreadable, or schema-invalid *blocking* input fails closed. Model-evaluation input is
  optional by design, so its absence is ordinary state rather than an error.
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

SOFTWARE_GATE_SCHEMA = "before-deploy-software-release-gate-v1"
SOFTWARE_GATE_AUTHORITY = "RELEASE_GATE"
SOFTWARE_GATE_EFFECT = "BLOCKS_RELEASE"

#: Software criteria that block a release, each with the reason code it emits when unsatisfied.
DETERMINISTIC_CI_NOT_GREEN = "DETERMINISTIC_CI_NOT_GREEN"
LINT_NOT_CLEAN = "LINT_NOT_CLEAN"
SELF_SCAN_NOT_PASS = "SELF_SCAN_NOT_PASS"
DISTRIBUTION_NOT_BUILT = "DISTRIBUTION_NOT_BUILT"
FULL_ASSURANCE_WORKFLOW_NOT_PROVEN = "FULL_ASSURANCE_WORKFLOW_NOT_PROVEN"
CLEAN_INSTALL_SMOKE_NOT_GREEN = "CLEAN_INSTALL_SMOKE_NOT_GREEN"
OPERATIONAL_FAULT_COVERAGE_INCOMPLETE = "OPERATIONAL_FAULT_COVERAGE_INCOMPLETE"

#: The self-scan outcome that certifies the tree. ``NOT_EVALUATED`` is deliberately not accepted:
#: a scan that ran no control has not checked anything, so it cannot certify a release.
SELF_SCAN_PASSING_OUTCOME = "PASS"

#: How the independent §3 evidence was supplied. A corpus definition proves that the pinned
#: repositories and labelled defects exist; it does not measure exploratory recall. Keeping the
#: states distinct keeps a report honest: "not measured" is a different fact from "measured and
#: failed", and an absent artifact is a third.
REAL_WORLD_STATE_MEASURED = "MEASURED"
REAL_WORLD_STATE_DEFINITION_ONLY = "DEFINITION_ONLY"
REAL_WORLD_STATE_ABSENT = "ABSENT"

#: Verifiers for the operational safety flags from criteria §2. Each flag is true only when every
#: declared verifier is present in the operational JUnit report and passed. Parametrized verifiers
#: are matched by their base node id and must all pass.
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

#: Verifiers for the end-to-end assurance workflow (criteria §4).
ASSURANCE_WORKFLOW_TESTS: tuple[str, ...] = (
    "tests/integration/test_scan_fixtures.py"
    "::test_python_observability_policy_blocks_print_and_passes_safe_fixture",
    "tests/integration/test_nextjs_fixture_scans.py"
    "::test_vulnerable_nextjs_fixture_blocks_on_new_nextjs_controls",
    "tests/integration/test_nextjs_fixture_scans.py"
    "::test_secure_nextjs_fixture_passes_and_reports_nextjs_profile",
)

#: Verifiers for the clean-install smoke (criteria §5). These skip unless an isolated install
#: exists, so a skipped run is correctly reported as absent evidence.
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
    """Raised when blocking gate inputs are missing, unreadable, or schema-invalid."""


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
    """Artifact paths supplied by the release workflow.

    The first seven are required and block the release. ``pilot_report`` and ``real_world_report``
    are model-evaluation evidence: optional, reported, and never blocking.
    """

    full_suite_report: Path
    lint_report: Path
    self_scan_report: Path
    operational_report: Path
    assurance_report: Path
    smoke_report: Path
    distribution_dir: Path
    pilot_report: Path | None = None
    real_world_report: Path | None = None


@dataclass(frozen=True)
class SoftwareAssessment:
    """The blocking verdict: may this build be released?"""

    decision: str
    reason_codes: tuple[str, ...]
    criteria: Mapping[str, bool]

    @property
    def ready(self) -> bool:
        return self.decision == "READY"


@dataclass(frozen=True)
class ModelEvaluationDiagnostic:
    """Non-blocking model-evaluation facts.

    Every field is informational. Nothing here changes ``SoftwareAssessment.decision``; the frozen
    maturity criteria for these numbers live in ``production_readiness.py`` and are gated by the
    Evaluation Lab workflows, not by this release path.
    """

    blocking: bool = False
    pilot_supplied: bool = False
    pilot_decision: str | None = None
    pilot_reason_codes: tuple[str, ...] = ()
    exploration_required_recall_lift: float | None = None
    false_positive_trap_rate_delta: float | None = None
    static_sufficient_recall_delta: float | None = None
    exploratory_prediction_stability: float | None = None
    real_world_state: str = REAL_WORLD_STATE_ABSENT
    real_world_repositories: int | None = None
    real_world_known_defects: int | None = None
    real_world_recall: float | None = None
    real_world_decision: str | None = None
    real_world_reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReleaseGateResult:
    software: SoftwareAssessment
    model_evaluation: ModelEvaluationDiagnostic
    artifacts: tuple[ArtifactDigest, ...]
    operational_scenarios: Mapping[str, bool]
    fault_scenarios_required: int
    fault_scenarios_passed: int
    schema_version: str = SOFTWARE_GATE_SCHEMA
    authority: str = SOFTWARE_GATE_AUTHORITY
    gate_effect: str = SOFTWARE_GATE_EFFECT

    @property
    def decision(self) -> str:
        return self.software.decision


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


def _base_node_id(node_id: str) -> str:
    """Strip a pytest parametrization suffix: ``x::test_y[a-b]`` -> ``x::test_y``.

    Only the test-name segment is trimmed, and only from its first ``[``, so a path containing
    brackets cannot be truncated by accident.
    """
    classname, separator, name = node_id.partition("::")
    if not separator:
        return node_id.split("[", 1)[0]
    return f"{classname}::{name.split('[', 1)[0]}"


def resolve_scenario(
    declared: Sequence[str],
    outcomes: Sequence[CaseOutcome],
    *,
    scenario: str,
) -> bool:
    """Return whether every declared verifier is present and passed.

    A declared verifier is matched by its base node id, so a parametrized test satisfies the
    scenario only when **every** parameterization passed. A verifier that is absent from the report
    is an input error: the scenario was never exercised, which is not the same as passing. A
    verifier that failed *or skipped* does not satisfy the scenario.
    """
    index: dict[str, list[str]] = {}
    for outcome in outcomes:
        index.setdefault(_base_node_id(outcome.node_id), []).append(outcome.status)

    satisfied = True
    for node_id in declared:
        classname, name = _dotted_node_id(node_id)
        statuses = index.get(f"{classname}::{name}")
        if statuses is None:
            raise ReadinessGateError(
                f"{scenario}: declared verifier {node_id!r} has no result in the report"
            )
        if any(status != _STATUS_PASSED for status in statuses):
            satisfied = False
    return satisfied


def _distribution_artifacts(distribution_dir: Path) -> tuple[tuple[Path, ...], bool]:
    """Return the built distributions and whether both a wheel and an sdist are present."""
    if not distribution_dir.is_dir():
        raise ReadinessGateError(
            f"distribution directory is unavailable: {distribution_dir}"
        )
    wheels = tuple(sorted(distribution_dir.glob("*.whl")))
    sdists = tuple(sorted(distribution_dir.glob("*.tar.gz")))
    return wheels + sdists, bool(wheels) and bool(sdists)


def lint_violation_count(path: Path) -> int:
    """Return the number of ``ruff check --output-format json`` violations in a lint report.

    An empty array is a clean run. A report that is not an array cannot establish cleanliness, so
    it is an input error rather than a failure.
    """
    if not path.is_file():
        raise ReadinessGateError(f"required readiness artifact lint-report is unavailable: {path}")
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReadinessGateError(f"lint report is not valid JSON: {path}") from error
    if not isinstance(payload, list):
        raise ReadinessGateError(
            "lint report must be the JSON array produced by ruff --output-format json"
        )
    return len(payload)


def self_scan_verdict(path: Path) -> tuple[str, int, int]:
    """Return ``(outcome, blocking_count, error_control_count)`` from a scan ``report.json``."""
    payload = _load_json("self-scan report", path)
    scan = payload.get("scan")
    if not isinstance(scan, Mapping):
        raise ReadinessGateError("self-scan report does not contain a scan object")
    decision = scan.get("decision")
    if not isinstance(decision, Mapping):
        raise ReadinessGateError("self-scan report does not contain a scan decision")
    outcome = decision.get("outcome")
    if not isinstance(outcome, str) or not outcome:
        raise ReadinessGateError("self-scan report decision has no outcome")
    blocking = decision.get("blocking_fingerprints") or []
    errors = decision.get("error_control_ids") or []
    if not isinstance(blocking, list) or not isinstance(errors, list):
        raise ReadinessGateError(
            "self-scan report blocking_fingerprints and error_control_ids must be arrays"
        )
    return outcome, len(blocking), len(errors)


def _optional_float(source: Mapping[str, Any], key: str) -> float | None:
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _optional_text(source: Mapping[str, Any], key: str) -> str | None:
    value = source.get(key)
    return value if isinstance(value, str) and value else None


def _optional_reason_codes(source: Mapping[str, Any]) -> tuple[str, ...]:
    codes = source.get("reason_codes")
    if not isinstance(codes, list):
        return ()
    return tuple(str(item) for item in codes)


def pilot_diagnostic(path: Path | None) -> dict[str, Any]:
    """Read the repeated-benchmark result as informational model-evaluation evidence.

    A malformed report is reported as unsupplied rather than raised: model-evaluation evidence
    must never be able to block a software release, and refusing to release because a *diagnostic*
    is malformed would reintroduce exactly the coupling this split removes.
    """
    empty = {
        "pilot_supplied": False,
        "pilot_decision": None,
        "pilot_reason_codes": (),
        "exploration_required_recall_lift": None,
        "false_positive_trap_rate_delta": None,
        "static_sufficient_recall_delta": None,
        "exploratory_prediction_stability": None,
    }
    if path is None or not path.is_file():
        return empty
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(payload, Mapping):
        return empty
    pilot = payload.get("caller_pilot")
    if not isinstance(pilot, Mapping):
        return empty
    exploratory = pilot.get("exploratory_variant")
    exploratory = exploratory if isinstance(exploratory, Mapping) else {}
    return {
        "pilot_supplied": True,
        "pilot_decision": _optional_text(pilot, "decision"),
        "pilot_reason_codes": _optional_reason_codes(pilot),
        "exploration_required_recall_lift": _optional_float(
            pilot, "exploration_required_recall_lift"
        ),
        "false_positive_trap_rate_delta": _optional_float(
            pilot, "false_positive_trap_rate_delta"
        ),
        "static_sufficient_recall_delta": _optional_float(
            pilot, "static_sufficient_recall_delta"
        ),
        "exploratory_prediction_stability": _optional_float(
            exploratory, "prediction_stability"
        ),
    }


def real_world_diagnostic(path: Path | None) -> dict[str, Any]:
    """Read the independent §3 result, or say precisely why it is unavailable.

    ``real-world-validation.yml`` validates the pinned corpus and cannot measure recall, because no
    producer for paired static/exploratory run records exists in this repository. Recognising that
    shape keeps the report honest instead of presenting a corpus definition as a §3 pass.
    """
    absent = {
        "real_world_state": REAL_WORLD_STATE_ABSENT,
        "real_world_repositories": None,
        "real_world_known_defects": None,
        "real_world_recall": None,
        "real_world_decision": None,
        "real_world_reason_codes": (),
    }
    if path is None or not path.is_file():
        return absent
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return absent
    if not isinstance(payload, Mapping):
        return absent

    report = payload.get("real_world_validation")
    if isinstance(report, Mapping):
        repositories = report.get("repository_count")
        known = report.get("known_defects")
        return {
            "real_world_state": REAL_WORLD_STATE_MEASURED,
            "real_world_repositories": repositories if isinstance(repositories, int) else None,
            "real_world_known_defects": known if isinstance(known, int) else None,
            "real_world_recall": _optional_float(report, "recall"),
            "real_world_decision": _optional_text(report, "decision"),
            "real_world_reason_codes": _optional_reason_codes(report),
        }

    repositories = payload.get("repositories")
    if isinstance(repositories, list):
        known = payload.get("known_defects")
        return {
            "real_world_state": REAL_WORLD_STATE_DEFINITION_ONLY,
            "real_world_repositories": len(repositories),
            "real_world_known_defects": known if isinstance(known, int) else None,
            "real_world_recall": None,
            "real_world_decision": None,
            "real_world_reason_codes": (),
        }
    return absent


def evaluate_release_gate(inputs: GateInputs) -> ReleaseGateResult:
    """Assemble software-release evidence from CI artifacts and decide whether to release."""
    artifacts = (
        _digest("full-suite-junit.xml", inputs.full_suite_report),
        _digest("lint-report.json", inputs.lint_report),
        _digest("self-scan-report.json", inputs.self_scan_report),
        _digest("operational-junit.xml", inputs.operational_report),
        _digest("assurance-junit.xml", inputs.assurance_report),
        _digest("smoke-junit.xml", inputs.smoke_report),
    )

    full_outcomes = parse_junit_outcomes(inputs.full_suite_report)
    if not full_outcomes:
        raise ReadinessGateError("full-suite JUnit report contains no test cases")
    # Skips are tolerated here: the deterministic suite legitimately skips capability-probed tests.
    # Only genuine failures and errors make deterministic CI not green.
    deterministic_ci_passed = not any(
        outcome.status == _STATUS_FAILED for outcome in full_outcomes
    )

    lint_passed = lint_violation_count(inputs.lint_report) == 0

    scan_outcome, blocking_findings, scan_errors = self_scan_verdict(inputs.self_scan_report)
    self_scan_passed = (
        scan_outcome == SELF_SCAN_PASSING_OUTCOME and blocking_findings == 0 and scan_errors == 0
    )

    distribution_paths, distribution_built = _distribution_artifacts(inputs.distribution_dir)
    artifacts = artifacts + tuple(
        ArtifactDigest(
            name=path.name,
            sha256=sha256(path.read_bytes()).hexdigest(),
            relative_path=path.name,
        )
        for path in distribution_paths
    )

    operational_outcomes = parse_junit_outcomes(inputs.operational_report)
    scenarios = {
        flag: resolve_scenario(declared, operational_outcomes, scenario=flag)
        for flag, declared in OPERATIONAL_SCENARIO_TESTS.items()
    }
    passed_scenarios = sum(1 for value in scenarios.values() if value)

    assurance_outcomes = parse_junit_outcomes(inputs.assurance_report)
    assurance_passed = resolve_scenario(
        ASSURANCE_WORKFLOW_TESTS, assurance_outcomes, scenario="assurance_workflow_passed"
    )

    smoke_outcomes = parse_junit_outcomes(inputs.smoke_report)
    smoke_passed = resolve_scenario(
        CLEAN_INSTALL_SMOKE_TESTS, smoke_outcomes, scenario="clean_install_smoke_passed"
    )

    criteria = {
        "deterministic_ci_passed": deterministic_ci_passed,
        "lint_passed": lint_passed,
        "self_scan_passed": self_scan_passed,
        "distribution_built": distribution_built,
        "assurance_workflow_passed": assurance_passed,
        "clean_install_smoke_passed": smoke_passed,
        "operational_fault_coverage_complete": (
            passed_scenarios == len(OPERATIONAL_SCENARIO_TESTS)
        ),
    }
    reason_codes = tuple(
        code
        for satisfied, code in (
            (deterministic_ci_passed, DETERMINISTIC_CI_NOT_GREEN),
            (lint_passed, LINT_NOT_CLEAN),
            (self_scan_passed, SELF_SCAN_NOT_PASS),
            (distribution_built, DISTRIBUTION_NOT_BUILT),
            (assurance_passed, FULL_ASSURANCE_WORKFLOW_NOT_PROVEN),
            (smoke_passed, CLEAN_INSTALL_SMOKE_NOT_GREEN),
            (passed_scenarios == len(OPERATIONAL_SCENARIO_TESTS), OPERATIONAL_FAULT_COVERAGE_INCOMPLETE),
        )
        if not satisfied
    )
    software = SoftwareAssessment(
        decision="READY" if not reason_codes else "NOT_READY",
        reason_codes=reason_codes,
        criteria=criteria,
    )

    diagnostic = ModelEvaluationDiagnostic(
        **pilot_diagnostic(inputs.pilot_report),
        **real_world_diagnostic(inputs.real_world_report),
    )

    return ReleaseGateResult(
        software=software,
        model_evaluation=diagnostic,
        artifacts=artifacts,
        operational_scenarios=scenarios,
        fault_scenarios_required=len(OPERATIONAL_SCENARIO_TESTS),
        fault_scenarios_passed=passed_scenarios,
    )


def _format_optional(value: object, *, suffix: str = "") -> str:
    if value is None:
        return "not supplied"
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return f"{value:.4f}{suffix}"
    return f"{value}{suffix}"


def render_release_gate_json(result: ReleaseGateResult) -> str:
    diagnostic = result.model_evaluation
    payload = {
        "schema_version": result.schema_version,
        "release_gate": {
            "authority": result.authority,
            "decision": result.decision,
            "gate_effect": result.gate_effect,
            "software_criteria": dict(sorted(result.software.criteria.items())),
            "software_reason_codes": list(result.software.reason_codes),
            "fault_scenarios_passed": result.fault_scenarios_passed,
            "fault_scenarios_required": result.fault_scenarios_required,
            "operational_scenarios": dict(sorted(result.operational_scenarios.items())),
            "model_evaluation": {
                "blocking": diagnostic.blocking,
                "pilot_supplied": diagnostic.pilot_supplied,
                "pilot_decision": diagnostic.pilot_decision,
                "pilot_reason_codes": list(diagnostic.pilot_reason_codes),
                "exploration_required_recall_lift": diagnostic.exploration_required_recall_lift,
                "false_positive_trap_rate_delta": diagnostic.false_positive_trap_rate_delta,
                "static_sufficient_recall_delta": diagnostic.static_sufficient_recall_delta,
                "exploratory_prediction_stability": (
                    diagnostic.exploratory_prediction_stability
                ),
                "real_world_state": diagnostic.real_world_state,
                "real_world_repositories": diagnostic.real_world_repositories,
                "real_world_known_defects": diagnostic.real_world_known_defects,
                "real_world_recall": diagnostic.real_world_recall,
                "real_world_decision": diagnostic.real_world_decision,
                "real_world_reason_codes": list(diagnostic.real_world_reason_codes),
            },
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
    diagnostic = result.model_evaluation
    lines = [
        "# Preflight Software Release Gate",
        "",
        f"- Decision: **{result.decision}**",
        f"- Authority: `{result.authority}` / gate effect `{result.gate_effect}`",
        f"- Operational scenarios: **{result.fault_scenarios_passed} / {result.fault_scenarios_required}**",
        f"- Retained evidence artifacts: **{len(result.artifacts)}**",
        "",
        "## Software criteria (blocking)",
        "",
    ]
    for name, satisfied in sorted(result.software.criteria.items()):
        lines.append(f"- `{name}`: {'passed' if satisfied else 'FAILED'}")
    lines.extend(["", "## Operational scenarios", ""])
    for name, passed in sorted(result.operational_scenarios.items()):
        lines.append(f"- `{name}`: {'passed' if passed else 'FAILED'}")
    lines.extend(
        [
            "",
            "## Model evaluation (informational — does not block this release)",
            "",
            (
                "- Repeated benchmark: "
                + (
                    f"`{diagnostic.pilot_decision}`"
                    if diagnostic.pilot_supplied
                    else "not supplied"
                )
            ),
            "- Exploration-required recall lift: "
            + _format_optional(diagnostic.exploration_required_recall_lift),
            "- False-positive-trap rate delta: "
            + _format_optional(diagnostic.false_positive_trap_rate_delta),
            "- Static-sufficient recall delta: "
            + _format_optional(diagnostic.static_sufficient_recall_delta),
            "- Exploratory prediction stability: "
            + _format_optional(diagnostic.exploratory_prediction_stability),
            f"- Independent §3 evidence: `{diagnostic.real_world_state}`",
            "- Independent §3 recall: " + _format_optional(diagnostic.real_world_recall),
            (
                "> These criteria (docs/PRODUCTION_READINESS_CRITERIA.md §1 and §3) measure an "
                "external model, not this software. They retain `gate_effect=NONE` and are "
                "evaluated by the Evaluation Lab workflows."
            ),
            "",
            "## Retained evidence",
            "",
        ]
    )
    for item in result.artifacts:
        lines.append(f"- `{item.name}` sha256 `{item.sha256}`")
    lines.extend(
        [
            "",
            "## Software reasons",
            "",
        ]
    )
    if result.software.reason_codes:
        lines.extend(f"- `{reason}`" for reason in result.software.reason_codes)
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "> A pass means the deterministic software criteria were satisfied by CI-produced",
            "> evidence. It does not assert that the advisory or model-evaluation planes are",
            "> mature, and it does not grant AI findings release authority.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="before-deploy-readiness-gate",
        description=(
            "Fail closed unless the deterministic software release criteria are satisfied by "
            "CI-produced artifacts. Model-evaluation evidence is reported, never blocking."
        ),
    )
    parser.add_argument("--full-suite-report", type=Path, required=True)
    parser.add_argument("--lint-report", type=Path, required=True)
    parser.add_argument("--self-scan-report", type=Path, required=True)
    parser.add_argument("--operational-report", type=Path, required=True)
    parser.add_argument("--assurance-report", type=Path, required=True)
    parser.add_argument("--smoke-report", type=Path, required=True)
    parser.add_argument("--distribution-dir", type=Path, required=True)
    parser.add_argument("--pilot-report", type=Path, default=None)
    parser.add_argument("--real-world-report", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    arguments = parser.parse_args(argv)

    inputs = GateInputs(
        full_suite_report=arguments.full_suite_report,
        lint_report=arguments.lint_report,
        self_scan_report=arguments.self_scan_report,
        operational_report=arguments.operational_report,
        assurance_report=arguments.assurance_report,
        smoke_report=arguments.smoke_report,
        distribution_dir=arguments.distribution_dir,
        pilot_report=arguments.pilot_report,
        real_world_report=arguments.real_world_report,
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
    if not result.software.ready:
        print(
            "release blocked: " + ", ".join(result.software.reason_codes),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ArtifactDigest",
    "ASSURANCE_WORKFLOW_TESTS",
    "CaseOutcome",
    "CLEAN_INSTALL_SMOKE_TESTS",
    "GateInputs",
    "ModelEvaluationDiagnostic",
    "OPERATIONAL_SCENARIO_TESTS",
    "REAL_WORLD_STATE_ABSENT",
    "REAL_WORLD_STATE_DEFINITION_ONLY",
    "REAL_WORLD_STATE_MEASURED",
    "ReadinessGateError",
    "ReleaseGateResult",
    "SOFTWARE_GATE_AUTHORITY",
    "SOFTWARE_GATE_EFFECT",
    "SOFTWARE_GATE_SCHEMA",
    "SoftwareAssessment",
    "evaluate_release_gate",
    "lint_violation_count",
    "main",
    "parse_junit_outcomes",
    "pilot_diagnostic",
    "real_world_diagnostic",
    "render_release_gate_json",
    "render_release_gate_markdown",
    "resolve_scenario",
    "self_scan_verdict",
]
