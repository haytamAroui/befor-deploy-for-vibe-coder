import json
import re
from collections import Counter
from pathlib import Path

from before_deploy.caller_pilot import (
    EXPLORATION_REQUIRED,
    FALSE_POSITIVE_TRAP,
    STATIC_SUFFICIENT,
    load_pilot_definition,
    prepare_initial_evidence,
)


CASES = Path("fixtures/caller-pilot-v2/cases.json")
CORPUS = Path("fixtures/caller-pilot-v2/corpus.json")


def test_caller_pilot_v2_is_balanced_and_opaque():
    definition = load_pilot_definition(CASES)
    counts = Counter(case.case_class for case in definition.cases)

    assert definition.name == "before-deploy-caller-pilot-v2"
    assert len(definition.cases) == 24
    assert counts == {
        STATIC_SUFFICIENT: 8,
        EXPLORATION_REQUIRED: 8,
        FALSE_POSITIVE_TRAP: 8,
    }
    assert len({case.case_id for case in definition.cases}) == 24
    assert len({case.symbol for case in definition.cases}) == 24
    assert all(re.fullmatch(r"C-[A-Z0-9]{4}", case.case_id) for case in definition.cases)


def test_caller_pilot_v2_model_visible_evidence_does_not_leak_hypothesis_class():
    definition = load_pilot_definition(CASES)
    forbidden = (
        "STATIC-SUFFICIENT",
        "EXPLORATION-REQUIRED",
        "FALSE-POSITIVE-TRAP",
        "DEFECT_ID",
    )

    for case in definition.cases:
        repository, prepared, evidence = prepare_initial_evidence(CASES, case.case_id)
        assert prepared == case
        visible = "\n".join(
            (
                evidence.evidence_id,
                evidence.path,
                evidence.content,
                case.symbol,
            )
        ).upper()
        assert all(token not in visible for token in forbidden)
        assert all(word not in evidence.path.lower() for word in ("static", "exploration", "trap"))

        initial_lines = (repository / evidence.path).read_text(encoding="utf-8").splitlines()
        assert case.initial_end_line <= len(initial_lines)
        assert case.symbol in evidence.content
        for region in case.regions:
            region_lines = (repository / region.path).read_text(encoding="utf-8").splitlines()
            assert region.end_line <= len(region_lines)


def test_caller_pilot_v2_corpus_matches_all_and_only_positive_cases():
    definition = load_pilot_definition(CASES)
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    defects = corpus["benchmark"]["defects"]

    expected = {case.defect_id for case in definition.cases if case.defect_id is not None}
    actual = {item["id"] for item in defects}

    assert corpus["benchmark"]["name"] == definition.name
    assert len(defects) == 16
    assert actual == expected
    assert all(case.defect_id is None for case in definition.cases if case.case_class == FALSE_POSITIVE_TRAP)
