import json
from pathlib import Path

from before_deploy.advisory import load_advisory_file
from before_deploy.caller_pilot import (
    EXPLORATION_REQUIRED,
    FALSE_POSITIVE_TRAP,
    STATIC_SUFFICIENT,
    evaluate_caller_pilot,
    load_pilot_definition,
    prepare_initial_evidence,
)


def _write(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_checked_in_pilot_has_balanced_hypothesis_classes_and_blinded_initial_context():
    cases_path = Path("fixtures/caller-pilot-v1/cases.json")
    definition = load_pilot_definition(cases_path)
    counts = {
        case_class: sum(item.case_class == case_class for item in definition.cases)
        for case_class in (STATIC_SUFFICIENT, EXPLORATION_REQUIRED, FALSE_POSITIVE_TRAP)
    }
    assert counts == {
        STATIC_SUFFICIENT: 4,
        EXPLORATION_REQUIRED: 4,
        FALSE_POSITIVE_TRAP: 4,
    }
    repository, case, evidence = prepare_initial_evidence(cases_path, "C-2JCP")
    assert repository.name == "repo"
    assert case.symbol == "target_url"
    assert evidence.path == "helpers_b.py"
    assert evidence.content == 'def target_url(request):\n    return request.query["url"]\n'

    leaked_terms = ("static", "exploration", "exp_", "trap", "false-positive")
    for item in definition.cases:
        _, prepared, prepared_evidence = prepare_initial_evidence(cases_path, item.case_id)
        exposed_identity = " ".join(
            (prepared.case_id, prepared.symbol, prepared_evidence.evidence_id, prepared_evidence.path)
        ).lower()
        assert not any(term in exposed_identity for term in leaked_terms)


def _fixture(tmp_path: Path, *, trap_fp: bool) -> tuple[Path, Path, Path]:
    corpus = tmp_path / "corpus.json"
    _write(
        corpus,
        {
            "schema_version": 1,
            "benchmark": {
                "name": "pilot-test",
                "defects": [
                    {"id": "S", "path": "s.py", "start_line": 2, "end_line": 2, "category": "security"},
                    {"id": "E", "path": "e.py", "start_line": 8, "end_line": 8, "category": "security"},
                ],
            },
        },
    )
    cases = tmp_path / "cases.json"
    _write(
        cases,
        {
            "schema_version": "before-deploy-caller-pilot-cases-v1",
            "pilot": {
                "name": "pilot-test",
                "repository": "repo",
                "cases": [
                    {"id":"S","class":"STATIC-SUFFICIENT","initial_path":"s.py","initial_start_line":1,"initial_end_line":2,"symbol":"s","regions":[{"path":"s.py","start_line":1,"end_line":2}],"defect_id":"S"},
                    {"id":"E","class":"EXPLORATION-REQUIRED","initial_path":"helper.py","initial_start_line":1,"initial_end_line":2,"symbol":"e","regions":[{"path":"e.py","start_line":8,"end_line":8}],"defect_id":"E"},
                    {"id":"T","class":"FALSE-POSITIVE-TRAP","initial_path":"trap.py","initial_start_line":1,"initial_end_line":2,"symbol":"t","regions":[{"path":"trap.py","start_line":1,"end_line":2}]},
                ],
            },
        },
    )
    static_file = tmp_path / "static.json"
    _write(
        static_file,
        {
            "source": "pilot",
            "findings": [
                {"message":"static visible","category":"security","severity":"high","path":"s.py","start_line":2}
            ],
        },
    )
    exploratory_findings = [
        {"message":"static visible","category":"security","severity":"high","path":"s.py","start_line":2},
        {"message":"caller reveals defect","category":"security","severity":"high","path":"e.py","start_line":8},
    ]
    if trap_fp:
        exploratory_findings.append(
            {"message":"trap false positive","category":"security","severity":"medium","path":"trap.py","start_line":1}
        )
    explore_file = tmp_path / "explore.json"
    _write(explore_file, {"source": "pilot", "findings": exploratory_findings})
    static = load_advisory_file(static_file)
    exploratory = load_advisory_file(explore_file)

    manifest = tmp_path / "runs.json"
    _write(
        manifest,
        {
            "schema_version": "before-deploy-comparative-benchmark-v1",
            "benchmark": {
                "name": "pilot-test",
                "runs": [
                    {
                        "run_id":"static-1","variant":"static","variant_role":"STATIC","repetition":1,
                        "advisory_file":static_file.name,"provider":"fixture","model":"fixture","context_bytes":100,
                        "tool_calls":0,"latency_ms":10,"cost_microusd":10,"input_tokens":10,"output_tokens":5,"tool_names":[],
                        "finding_evidence":[
                            {"fingerprint":item.fingerprint,"evidence_dependency":"initial_context_only","supported_claim":True,"citation_correct":True}
                            for item in static.findings
                        ]
                    },
                    {
                        "run_id":"explore-1","variant":"callers","variant_role":"EXPLORATORY","repetition":1,
                        "advisory_file":explore_file.name,"provider":"fixture","model":"fixture","context_bytes":160,
                        "tool_calls":1,"latency_ms":12,"cost_microusd":12,"input_tokens":12,"output_tokens":6,"tool_names":["find_callers"],
                        "finding_evidence":[
                            {
                                "fingerprint":item.fingerprint,
                                "evidence_dependency":("expanded_context_used" if item.location and item.location.path != "s.py" else "initial_context_only"),
                                "supported_claim":True,"citation_correct":True
                            }
                            for item in exploratory.findings
                        ]
                    }
                ]
            }
        },
    )
    return corpus, cases, manifest


def test_pilot_go_requires_real_exploration_lift_without_trap_regression(tmp_path):
    corpus, cases, manifest = _fixture(tmp_path, trap_fp=False)
    result = evaluate_caller_pilot(
        corpus_path=corpus,
        comparative_manifest_path=manifest,
        cases_path=cases,
    )
    assert result.decision == "GO"
    assert result.exploration_required_recall_lift == 1.0
    assert result.false_positive_trap_rate_delta == 0.0
    assert result.exploratory_variant.exploration_attributable_tp == 1
    assert result.reason_codes == ()


def test_pilot_stops_when_exploration_adds_false_positive_trap(tmp_path):
    corpus, cases, manifest = _fixture(tmp_path, trap_fp=True)
    result = evaluate_caller_pilot(
        corpus_path=corpus,
        comparative_manifest_path=manifest,
        cases_path=cases,
    )
    assert result.decision == "STOP"
    assert "FALSE_POSITIVE_TRAP_RATE_INCREASED" in result.reason_codes
    assert result.exploratory_variant.exploration_attributable_fp == 1
