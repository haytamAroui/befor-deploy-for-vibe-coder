import json
from json import loads
from pathlib import Path

import pytest

from before_deploy.real_world_validation import (
    REAL_WORLD_GATE_EFFECT,
    RealWorldVariantObservation,
    assert_model_visible_payload_is_blinded,
    evaluate_real_world_validation,
    load_real_world_run,
    real_world_readiness_evidence,
    render_real_world_validated_json,
    render_real_world_validated_markdown,
    validate_real_world_benchmark,
)
from before_deploy.review_benchmark_corpus import BenchmarkCorpusValidation


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fake_provenance_validator(corpus_path, provenance_path, root):
    declaration = loads(provenance_path.read_text(encoding="utf-8"))
    corpus = loads(corpus_path.read_text(encoding="utf-8"))
    return BenchmarkCorpusValidation(
        name=declaration.get("name", corpus["benchmark"]["name"]),
        source_repository=declaration["source_repository"],
        source_commit=declaration["source_commit"],
        positive_file_count=declaration["positive_file_count"],
        negative_file_count=declaration["negative_file_count"],
        defect_count=len(corpus["benchmark"]["defects"]),
    )


def _corpus(root: Path, bucket: str, name: str, defect_ids: tuple[str, ...]) -> str:
    defects = [
        {
            "id": defect_id,
            "path": f"fixtures/real-world-validation/{bucket}/src/app.py",
            "start_line": 1,
            "end_line": 2,
            "category": "security",
        }
        for defect_id in defect_ids
    ]
    relative = f"fixtures/real-world-validation/{bucket}/corpus.json"
    _write(root / relative, {"schema_version": 1, "benchmark": {"name": name, "defects": defects}})
    return relative


def _repository(
    root: Path,
    *,
    bucket: str,
    repository_id: str = "RW-3F7A",
    repository: str = "https://github.com/example-one/alpha",
    commit: str = "a" * 40,
    upstream_revision: str = "1.2.3",
    defect_ids: tuple[str, ...] = ("D-0001", "D-0002"),
    provenance_overrides: dict | None = None,
    write_license_notice: bool = True,
    name: str | None = None,
) -> dict:
    corpus = _corpus(root, bucket, name or f"real-world-{bucket}", defect_ids)
    if write_license_notice:
        notice = root / f"fixtures/real-world-validation/{bucket}/NOTICE"
        notice.parent.mkdir(parents=True, exist_ok=True)
        notice.write_text("upstream license notice", encoding="utf-8")
    provenance = {
        "name": name or f"real-world-{bucket}",
        "source_repository": repository,
        "source_commit": commit,
        "positive_file_count": 1,
        "negative_file_count": 1,
    }
    provenance.update(provenance_overrides or {})
    provenance_relative = f"fixtures/real-world-validation/{bucket}/manifest.json"
    _write(root / provenance_relative, provenance)
    return {
        "repository_id": repository_id,
        "repository": repository,
        "commit": commit,
        "upstream_revision": upstream_revision,
        "corpus": corpus,
        "provenance": provenance_relative,
        "license_notice": f"fixtures/real-world-validation/{bucket}/NOTICE",
    }


def _manifest(root: Path, repositories: list[dict], *, name: str = "real-world-seed") -> Path:
    path = root / "fixtures/real-world-validation/validation.json"
    _write(
        path,
        {
            "schema_version": "before-deploy-real-world-validation-v1",
            "validation": {"name": name, "repositories": repositories},
        },
    )
    return path


def _three_repository_manifest(root: Path) -> Path:
    return _manifest(
        root,
        [
            _repository(
                root,
                bucket="alpha",
                repository_id="RW-3F7A",
                repository="https://github.com/example-one/alpha",
                commit="a" * 40,
                defect_ids=("D-0001", "D-0002"),
            ),
            _repository(
                root,
                bucket="beta",
                repository_id="RW-9K2M",
                repository="https://github.com/example-two/beta",
                commit="b" * 40,
                upstream_revision="2.0.0",
                defect_ids=("D-0003", "D-0004"),
            ),
            _repository(
                root,
                bucket="gamma",
                repository_id="RW-5P8Q",
                repository="https://github.com/example-three/gamma",
                commit="c" * 40,
                upstream_revision="3.1.0",
                defect_ids=("D-0005", "D-0006"),
            ),
        ],
    )


def _definition(root: Path):
    return validate_real_world_benchmark(
        _three_repository_manifest(root),
        root,
        provenance_validator=_fake_provenance_validator,
    )


def test_three_unrelated_repositories_validate_as_blinded_and_independent(tmp_path):
    definition = _definition(tmp_path)
    assert definition.repository_count == 3
    assert definition.known_defects == 6
    assert definition.defect_ids == ("D-0001", "D-0002", "D-0003", "D-0004", "D-0005", "D-0006")
    assert definition.reviewed_file_count == 6
    assert definition.blinded is True
    assert definition.independent is True


def test_passing_run_requires_recall_tp_advantage_and_no_fp_regression(tmp_path):
    definition = _definition(tmp_path)
    result = evaluate_real_world_validation(
        definition,
        static=RealWorldVariantObservation(
            variant_role="STATIC",
            detected_defect_ids=("D-0001",),
            exploration_attributable_tp=0,
            exploration_attributable_fp=0,
            false_positive_count=1,
        ),
        exploratory=RealWorldVariantObservation(
            variant_role="EXPLORATORY",
            detected_defect_ids=("D-0001", "D-0003", "D-0004", "D-0005"),
            exploration_attributable_tp=3,
            exploration_attributable_fp=1,
            false_positive_count=1,
        ),
    )
    assert result.decision == "PASS"
    assert result.reason_codes == ()
    assert result.recall == pytest.approx(4 / 6)
    assert result.static_false_positive_rate == pytest.approx(1 / 6)
    assert result.exploratory_false_positive_rate == pytest.approx(1 / 6)
    assert result.gate_effect == REAL_WORLD_GATE_EFFECT == "NONE"
    rendered = render_real_world_validated_markdown(result)
    assert "Independent Real-World Validation" in rendered
    assert "gate effect `NONE`" in rendered
    assert '"gate_effect": "NONE"' in render_real_world_validated_json(result)


def test_failing_run_reports_every_frozen_section_three_condition(tmp_path):
    definition = _definition(tmp_path)
    result = evaluate_real_world_validation(
        definition,
        static=RealWorldVariantObservation(
            variant_role="STATIC",
            detected_defect_ids=("D-0001",),
            exploration_attributable_tp=0,
            exploration_attributable_fp=0,
            false_positive_count=0,
        ),
        exploratory=RealWorldVariantObservation(
            variant_role="EXPLORATORY",
            detected_defect_ids=("D-0001", "D-0002"),
            exploration_attributable_tp=2,
            exploration_attributable_fp=2,
            false_positive_count=3,
            uncited_credit_count=1,
        ),
    )
    assert result.decision == "FAIL"
    assert set(result.reason_codes) >= {
        "INSUFFICIENT_REAL_WORLD_RECALL",
        "REAL_WORLD_EXPLORATION_TP_NOT_GREATER_THAN_FP",
        "REAL_WORLD_FALSE_POSITIVE_RATE_REGRESSED",
        "REAL_WORLD_CREDITED_FINDING_WITHOUT_CITED_EVIDENCE",
    }


def test_insufficient_repository_and_defect_counts_fail_closed(tmp_path):
    manifest = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                defect_ids=("D-0001",),
            )
        ],
    )
    definition = validate_real_world_benchmark(
        manifest, tmp_path, provenance_validator=_fake_provenance_validator
    )
    result = evaluate_real_world_validation(
        definition,
        static=RealWorldVariantObservation(
            variant_role="STATIC",
            detected_defect_ids=("D-0001",),
            exploration_attributable_tp=0,
            exploration_attributable_fp=0,
            false_positive_count=0,
        ),
        exploratory=RealWorldVariantObservation(
            variant_role="EXPLORATORY",
            detected_defect_ids=("D-0001",),
            exploration_attributable_tp=1,
            exploration_attributable_fp=0,
            false_positive_count=0,
        ),
    )
    assert result.decision == "FAIL"
    assert result.blinded is True
    assert result.independent is False
    assert set(result.reason_codes) >= {
        "INSUFFICIENT_REAL_WORLD_REPOSITORIES",
        "INSUFFICIENT_REAL_WORLD_DEFECTS",
        "REAL_WORLD_BENCHMARK_NOT_INDEPENDENT",
    }


def test_manifest_rejects_non_opaque_duplicate_and_mismatched_provenance(tmp_path):
    manifest = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="alpha-repo",
                commit="a" * 40,
                defect_ids=("D-0001",),
            )
        ],
    )
    with pytest.raises(ValueError, match="must be opaque"):
        validate_real_world_benchmark(
            manifest, tmp_path, provenance_validator=_fake_provenance_validator
        )

    duplicated = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                defect_ids=("D-0001",),
            ),
            _repository(
                tmp_path,
                bucket="beta",
                repository_id="RW-9K2M",
                repository="https://github.com/example-two/beta",
                commit="a" * 40,
                upstream_revision="2.0.0",
                defect_ids=("D-0002",),
            ),
        ],
    )
    # One local commit may vendor several snapshots, so duplicate snapshots are accepted and
    # independence is enforced upstream instead.
    shared_commit = validate_real_world_benchmark(
        duplicated, tmp_path, provenance_validator=_fake_provenance_validator
    )
    assert shared_commit.repository_count == 2

    repeated_upstream = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                upstream_revision="1.2.3",
                defect_ids=("D-0001",),
            ),
            _repository(
                tmp_path,
                bucket="beta",
                repository_id="RW-9K2M",
                repository="https://github.com/example-two/beta",
                commit="b" * 40,
                upstream_revision="1.2.3",
                defect_ids=("D-0002",),
            ),
        ],
    )
    with pytest.raises(ValueError, match="Duplicate real-world validation upstream revision"):
        validate_real_world_benchmark(
            repeated_upstream, tmp_path, provenance_validator=_fake_provenance_validator
        )

    mismatched = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                defect_ids=("D-0001",),
                provenance_overrides={"source_commit": "d" * 40},
            )
        ],
    )
    with pytest.raises(ValueError, match="its provenance manifest validates"):
        validate_real_world_benchmark(
            mismatched, tmp_path, provenance_validator=_fake_provenance_validator
        )


def test_manifest_requires_license_notice_and_unique_global_defect_ids(tmp_path):
    manifest = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                defect_ids=("D-0001",),
                write_license_notice=False,
            )
        ],
    )
    with pytest.raises(ValueError, match="license notice file does not exist"):
        validate_real_world_benchmark(
            manifest, tmp_path, provenance_validator=_fake_provenance_validator
        )

    shared = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                defect_ids=("D-0001",),
            ),
            _repository(
                tmp_path,
                bucket="beta",
                repository_id="RW-9K2M",
                repository="https://github.com/example-two/beta",
                commit="b" * 40,
                upstream_revision="2.0.0",
                defect_ids=("D-0001",),
            ),
        ],
    )
    with pytest.raises(ValueError, match="globally unique"):
        validate_real_world_benchmark(
            shared, tmp_path, provenance_validator=_fake_provenance_validator
        )


def test_advisory_style_defect_ids_are_rejected_as_non_opaque(tmp_path):
    manifest = _manifest(
        tmp_path,
        [
            _repository(
                tmp_path,
                bucket="alpha",
                repository_id="RW-3F7A",
                commit="a" * 40,
                defect_ids=("CVE-2021-44228",),
            )
        ],
    )
    with pytest.raises(ValueError, match="must be opaque"):
        validate_real_world_benchmark(
            manifest, tmp_path, provenance_validator=_fake_provenance_validator
        )


def test_model_visible_blinding_check_is_fail_closed():
    clean = {
        "evidence_id": "rw-initial:3F7A",
        "path": "fixtures/real-world-validation/alpha/src/app.py",
        "content": "def handler(request):\n    return request.query['x']\n",
        "content_sha256": "0" * 64,
        "source_start_line": 1,
        "source_end_line": 2,
    }
    assert_model_visible_payload_is_blinded(clean, forbidden_tokens=("fix-commit-sha",))

    with pytest.raises(ValueError, match="evaluator-only token"):
        assert_model_visible_payload_is_blinded(clean, forbidden_tokens=("fixtures/real-world",))

    with pytest.raises(ValueError, match="leaks a cve identifier"):
        assert_model_visible_payload_is_blinded(
            {**clean, "content": "CVE-2021-44228"},
        )

    with pytest.raises(ValueError, match="evaluator-only keys: defect_id"):
        assert_model_visible_payload_is_blinded({**clean, "defect_id": "D-0001"})

    with pytest.raises(ValueError, match="evaluator-only keys: expected_start_line"):
        assert_model_visible_payload_is_blinded(
            {**clean, "expected_start_line": 12},
        )


def test_readiness_projection_populates_frozen_evidence_fields(tmp_path):
    definition = _definition(tmp_path)
    result = evaluate_real_world_validation(
        definition,
        static=RealWorldVariantObservation(
            variant_role="STATIC",
            detected_defect_ids=("D-0001",),
            exploration_attributable_tp=0,
            exploration_attributable_fp=0,
            false_positive_count=1,
        ),
        exploratory=RealWorldVariantObservation(
            variant_role="EXPLORATORY",
            detected_defect_ids=("D-0001", "D-0003", "D-0004", "D-0005"),
            exploration_attributable_tp=3,
            exploration_attributable_fp=1,
            false_positive_count=1,
        ),
    )
    projection = real_world_readiness_evidence(result)
    assert set(projection) == {
        "real_world_repository_count",
        "real_world_known_defects",
        "real_world_detected_defects",
        "real_world_exploration_attributable_tp",
        "real_world_exploration_attributable_fp",
        "real_world_static_false_positive_rate",
        "real_world_exploratory_false_positive_rate",
        "real_world_blinded",
        "real_world_independent",
    }
    assert projection["real_world_repository_count"] == 3
    assert projection["real_world_detected_defects"] == 4
    assert projection["real_world_blinded"] is True
    assert projection["real_world_independent"] is True


def test_run_record_loader_is_strict_and_defaults_counts_to_zero(tmp_path):
    path = tmp_path / "run.json"
    _write(
        path,
        {
            "schema_version": "before-deploy-real-world-run-v1",
            "static": {"detected_defect_ids": ["D-0001"]},
            "exploratory": {
                "detected_defect_ids": ["D-0001", "D-0003"],
                "exploration_attributable_tp": 2,
            },
        },
    )
    static, exploratory = load_real_world_run(path)
    assert static.variant_role == "STATIC"
    assert static.detected_defect_ids == ("D-0001",)
    assert static.exploration_attributable_tp == 0
    assert exploratory.exploration_attributable_fp == 0
    assert exploratory.detected_defect_ids == ("D-0001", "D-0003")

    _write(path, {"schema_version": "other", "static": {}, "exploratory": {}})
    with pytest.raises(ValueError, match="Unsupported real-world run record schema"):
        load_real_world_run(path)

    _write(
        path,
        {
            "schema_version": "before-deploy-real-world-run-v1",
            "static": {"detected_defect_ids": [], "expected_locations": [3]},
            "exploratory": {"detected_defect_ids": []},
        },
    )
    with pytest.raises(ValueError, match="unsupported fields: expected_locations"):
        load_real_world_run(path)

    _write(
        path,
        {
            "schema_version": "before-deploy-real-world-run-v1",
            "static": {"detected_defect_ids": [], "exploration_attributable_tp": -1},
            "exploratory": {"detected_defect_ids": []},
        },
    )
    with pytest.raises(ValueError, match="non-negative integer"):
        load_real_world_run(path)


def test_cli_exit_codes_and_reports(tmp_path, monkeypatch):
    from before_deploy import real_world_validation_cli as cli

    definition = _definition(tmp_path)
    monkeypatch.setattr(cli, "validate_real_world_benchmark", lambda *args, **kwargs: definition)
    manifest = tmp_path / "aggregate.json"
    _write(manifest, {"schema_version": "before-deploy-real-world-validation-v1"})

    output = tmp_path / "reports"
    passing = tmp_path / "passing.json"
    _write(
        passing,
        {
            "schema_version": "before-deploy-real-world-run-v1",
            "static": {"detected_defect_ids": ["D-0001"], "false_positive_count": 1},
            "exploratory": {
                "detected_defect_ids": ["D-0001", "D-0003", "D-0004", "D-0005"],
                "exploration_attributable_tp": 3,
                "exploration_attributable_fp": 1,
                "false_positive_count": 1,
            },
        },
    )
    assert cli.main([
        "--manifest",
        str(manifest),
        "--run",
        str(passing),
        "--output-dir",
        str(output),
    ]) == 0
    assert (output / "real-world-validation.json").is_file()
    assert (output / "real-world-validation.md").is_file()

    failing = tmp_path / "failing.json"
    _write(
        failing,
        {
            "schema_version": "before-deploy-real-world-run-v1",
            "static": {"detected_defect_ids": [], "false_positive_count": 0},
            "exploratory": {"detected_defect_ids": ["D-0001"], "exploration_attributable_tp": 0},
        },
    )
    assert cli.main([
        "--manifest",
        str(manifest),
        "--run",
        str(failing),
        "--output-dir",
        str(output),
        "--format",
        "json",
    ]) == 1

    assert cli.main(["--manifest", str(manifest)]) == 0


def test_cli_missing_manifest_is_a_non_gate_input_error(tmp_path):
    from before_deploy import real_world_validation_cli as cli

    assert cli.main(["--manifest", str(tmp_path / "missing.json")]) == 2

    unsupported = tmp_path / "unsupported.json"
    _write(unsupported, {"schema_version": "other"})
    assert cli.main(["--manifest", str(unsupported)]) == 2


def test_unknown_credited_defect_is_rejected(tmp_path):
    definition = _definition(tmp_path)
    with pytest.raises(ValueError, match="must belong to the frozen corpus"):
        evaluate_real_world_validation(
            definition,
            static=RealWorldVariantObservation(
                variant_role="STATIC",
                detected_defect_ids=(),
                exploration_attributable_tp=0,
                exploration_attributable_fp=0,
                false_positive_count=0,
            ),
            exploratory=RealWorldVariantObservation(
                variant_role="EXPLORATORY",
                detected_defect_ids=("D-9999",),
                exploration_attributable_tp=1,
                exploration_attributable_fp=0,
                false_positive_count=0,
            ),
        )
