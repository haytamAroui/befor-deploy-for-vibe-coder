import json
from pathlib import Path

import pytest

from before_deploy.advisory import load_advisory_file
from before_deploy.comparative_benchmark import evaluate_comparative_manifest
from before_deploy.comparative_benchmark_cli import main


def _write(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _corpus(tmp_path: Path) -> Path:
    path = tmp_path / "corpus.json"
    _write(
        path,
        {
            "schema_version": 1,
            "benchmark": {
                "name": "caller-pilot",
                "defects": [
                    {
                        "id": "AUTH-1",
                        "path": "app/service.py",
                        "start_line": 10,
                        "end_line": 10,
                        "category": "security",
                        "severity": "high",
                    }
                ],
            },
        },
    )
    return path


def _advisory(tmp_path: Path, name: str, findings: list[dict]) -> tuple[Path, tuple[str, ...]]:
    path = tmp_path / name
    _write(path, {"source": "pilot", "findings": findings})
    loaded = load_advisory_file(path)
    return path, tuple(item.fingerprint for item in loaded.findings)


def _run(
    *,
    run_id: str,
    variant: str,
    role: str,
    repetition: int,
    advisory_file: str,
    fingerprints: tuple[str, ...],
    dependency: str = "initial_context_only",
    tool_calls: int = 0,
    tool_names: list[str] | None = None,
):
    return {
        "run_id": run_id,
        "variant": variant,
        "variant_role": role,
        "repetition": repetition,
        "advisory_file": advisory_file,
        "provider": "fixture",
        "model": "fixture-model",
        "context_bytes": 1000 + tool_calls * 100,
        "tool_calls": tool_calls,
        "latency_ms": 100 + tool_calls * 20,
        "cost_microusd": 1000 + tool_calls * 200,
        "input_tokens": 100,
        "output_tokens": 20,
        "tool_names": tool_names or [],
        "finding_evidence": [
            {
                "fingerprint": fingerprint,
                "evidence_dependency": dependency,
                "supported_claim": True,
                "citation_correct": True,
            }
            for fingerprint in fingerprints
        ],
    }


def test_comparative_benchmark_attributes_exploration_tp_and_repeated_stability(tmp_path):
    corpus = _corpus(tmp_path)
    static_path, static_fps = _advisory(tmp_path, "static.json", [])
    finding = {
        "title": "Missing tenant authorization",
        "message": "A caller reaches the helper without the required tenant check.",
        "category": "security",
        "severity": "high",
        "path": "app/service.py",
        "start_line": 10,
        "end_line": 10,
    }
    explore_one, explore_fps = _advisory(tmp_path, "explore-1.json", [finding])
    explore_two, explore_fps_two = _advisory(tmp_path, "explore-2.json", [finding])
    assert explore_fps == explore_fps_two

    manifest = tmp_path / "manifest.json"
    _write(
        manifest,
        {
            "schema_version": "before-deploy-comparative-benchmark-v1",
            "benchmark": {
                "name": "pilot",
                "runs": [
                    _run(
                        run_id="static-1",
                        variant="static-ai",
                        role="STATIC",
                        repetition=1,
                        advisory_file=static_path.name,
                        fingerprints=static_fps,
                    ),
                    _run(
                        run_id="callers-1",
                        variant="ai-find-callers",
                        role="EXPLORATORY",
                        repetition=1,
                        advisory_file=explore_one.name,
                        fingerprints=explore_fps,
                        dependency="expanded_context_used",
                        tool_calls=1,
                        tool_names=["find_callers"],
                    ),
                    _run(
                        run_id="callers-2",
                        variant="ai-find-callers",
                        role="EXPLORATORY",
                        repetition=2,
                        advisory_file=explore_two.name,
                        fingerprints=explore_fps_two,
                        dependency="expanded_context_used",
                        tool_calls=1,
                        tool_names=["find_callers"],
                    ),
                ],
            },
        },
    )

    result = evaluate_comparative_manifest(corpus, manifest)
    variants = {item.variant: item for item in result.variants}
    assert variants["static-ai"].mean_recall == 0.0
    exploratory = variants["ai-find-callers"]
    assert exploratory.mean_recall == 1.0
    assert exploratory.exploration_attributable_tp == 2
    assert exploratory.exploration_attributable_fp == 0
    assert exploratory.supported_claim_rate == 1.0
    assert exploratory.citation_correct_rate == 1.0
    assert exploratory.prediction_stability == 1.0
    assert result.gate_effect == "NONE"


def test_claim_stability_ignores_wording_and_detects_location_drift(tmp_path):
    """Claim-key stability measures the prediction; exact stability measures the prose."""
    corpus = _corpus(tmp_path)

    def claim(title: str, message: str, start_line: int) -> dict:
        return {
            "title": title,
            "message": message,
            "category": "security",
            "severity": "high",
            "path": "app/service.py",
            "start_line": start_line,
            "end_line": start_line,
        }

    rewording_a, fps_a = _advisory(
        tmp_path, "rewording-a.json", [claim("Missing tenant check", "first wording", 10)]
    )
    rewording_b, fps_b = _advisory(
        tmp_path, "rewording-b.json", [claim("Absent tenant guard", "second wording", 10)]
    )
    assert set(fps_a).isdisjoint(fps_b)

    drift_a, drift_fps_a = _advisory(
        tmp_path, "drift-a.json", [claim("Caller bypass", "same wording", 10)]
    )
    drift_b, drift_fps_b = _advisory(
        tmp_path, "drift-b.json", [claim("Caller bypass", "same wording", 11)]
    )

    manifest = tmp_path / "manifest.json"
    _write(
        manifest,
        {
            "schema_version": "before-deploy-comparative-benchmark-v1",
            "benchmark": {
                "name": "stability",
                "runs": [
                    _run(
                        run_id="rewording-1",
                        variant="rewording",
                        role="EXPLORATORY",
                        repetition=1,
                        advisory_file=rewording_a.name,
                        fingerprints=fps_a,
                        dependency="expanded_context_used",
                        tool_calls=1,
                        tool_names=["find_callers"],
                    ),
                    _run(
                        run_id="rewording-2",
                        variant="rewording",
                        role="EXPLORATORY",
                        repetition=2,
                        advisory_file=rewording_b.name,
                        fingerprints=fps_b,
                        dependency="expanded_context_used",
                        tool_calls=1,
                        tool_names=["find_callers"],
                    ),
                    _run(
                        run_id="drift-1",
                        variant="drift",
                        role="EXPLORATORY",
                        repetition=1,
                        advisory_file=drift_a.name,
                        fingerprints=drift_fps_a,
                        dependency="expanded_context_used",
                        tool_calls=1,
                        tool_names=["find_callers"],
                    ),
                    _run(
                        run_id="drift-2",
                        variant="drift",
                        role="EXPLORATORY",
                        repetition=2,
                        advisory_file=drift_b.name,
                        fingerprints=drift_fps_b,
                        dependency="expanded_context_used",
                        tool_calls=1,
                        tool_names=["find_callers"],
                    ),
                ],
            },
        },
    )

    variants = {item.variant: item for item in evaluate_comparative_manifest(corpus, manifest).variants}

    rewording = variants["rewording"]
    assert rewording.mean_recall == 1.0
    assert rewording.prediction_stability == 1.0
    assert rewording.exact_prediction_stability == 0.0

    # A genuinely different prediction lowers both measurements, so the claim-key metric keeps
    # discriminating power rather than saturating at 1.0.
    drift = variants["drift"]
    assert drift.prediction_stability == 0.0
    assert drift.exact_prediction_stability == 0.0


def test_comparative_benchmark_rejects_missing_finding_attribution(tmp_path):
    corpus = _corpus(tmp_path)
    advisory, _ = _advisory(
        tmp_path,
        "finding.json",
        [
            {
                "message": "caller evidence",
                "category": "security",
                "path": "app/service.py",
                "start_line": 10,
            }
        ],
    )
    run = _run(
        run_id="bad",
        variant="explore",
        role="EXPLORATORY",
        repetition=1,
        advisory_file=advisory.name,
        fingerprints=(),
        tool_calls=1,
        tool_names=["find_callers"],
    )
    manifest = tmp_path / "manifest.json"
    _write(
        manifest,
        {
            "schema_version": "before-deploy-comparative-benchmark-v1",
            "benchmark": {"name": "bad", "runs": [run]},
        },
    )
    with pytest.raises(ValueError, match="attribution mismatch"):
        evaluate_comparative_manifest(corpus, manifest)


def test_static_variant_rejects_tool_usage_and_cli_writes_reports(tmp_path):
    corpus = _corpus(tmp_path)
    advisory, fingerprints = _advisory(tmp_path, "empty.json", [])
    bad_manifest = tmp_path / "bad.json"
    _write(
        bad_manifest,
        {
            "schema_version": "before-deploy-comparative-benchmark-v1",
            "benchmark": {
                "name": "bad-static",
                "runs": [
                    _run(
                        run_id="static",
                        variant="static",
                        role="STATIC",
                        repetition=1,
                        advisory_file=advisory.name,
                        fingerprints=fingerprints,
                        tool_calls=1,
                        tool_names=["find_callers"],
                    )
                ],
            },
        },
    )
    assert main(["--corpus", str(corpus), "--manifest", str(bad_manifest)]) == 2

    good_manifest = tmp_path / "good.json"
    _write(
        good_manifest,
        {
            "schema_version": "before-deploy-comparative-benchmark-v1",
            "benchmark": {
                "name": "good-static",
                "runs": [
                    _run(
                        run_id="static",
                        variant="static",
                        role="STATIC",
                        repetition=1,
                        advisory_file=advisory.name,
                        fingerprints=fingerprints,
                    )
                ],
            },
        },
    )
    output = tmp_path / "reports"
    assert main([
        "--corpus",
        str(corpus),
        "--manifest",
        str(good_manifest),
        "--output-dir",
        str(output),
        "--format",
        "json",
    ]) == 0
    assert (output / "comparative-benchmark.json").is_file()
    assert (output / "comparative-benchmark.md").is_file()
