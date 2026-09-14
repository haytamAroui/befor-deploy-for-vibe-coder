from __future__ import annotations

from datetime import datetime, timezone
from json import loads

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport, UnifiedReviewResult
from before_deploy.models import (
    Confidence,
    Finding,
    GateOutcome,
    Location,
    PolicyDecision,
    ScanManifest,
    ScanResult,
    Severity,
)
from before_deploy.review_session import (
    ReviewSession,
    SessionFinding,
    SessionSource,
    build_review_session,
    compare_review_sessions,
    load_review_session,
    render_review_delta_json,
    render_review_delta_markdown,
    render_review_session_json,
    review_delta_error,
)


def _finding(plane: str, fingerprint: str, title: str | None = None) -> SessionFinding:
    return SessionFinding(
        plane=plane,
        fingerprint=fingerprint,
        title=title or fingerprint,
        severity="HIGH" if plane == "DETERMINISTIC" else "high",
        source="SEC-TEST-001" if plane == "DETERMINISTIC" else "open-code-review",
        location=Location(path="src/app.py", start_line=1, end_line=1),
    )


def _session(
    session_id: str,
    *,
    repository_identity: str = "repo-identity",
    deterministic: tuple[SessionFinding, ...] = (),
    advisory: tuple[SessionFinding, ...] = (),
    sources: tuple[SessionSource, ...] = (),
) -> ReviewSession:
    return ReviewSession(
        session_id=session_id,
        repository_identity=repository_identity,
        identity_basis="git_root_commits",
        git_revision="abc123",
        policy_digest="policy-digest",
        deterministic_findings=deterministic,
        advisory_findings=advisory,
        advisory_sources=sources,
    )


def test_review_delta_classifies_new_persisting_and_absent_without_claiming_fixed():
    baseline = _session(
        "baseline",
        deterministic=(_finding("DETERMINISTIC", "det-a"), _finding("DETERMINISTIC", "det-old")),
        advisory=(_finding("ADVISORY", "adv-a"), _finding("ADVISORY", "adv-old")),
    )
    current = _session(
        "current",
        deterministic=(_finding("DETERMINISTIC", "det-a"), _finding("DETERMINISTIC", "det-new")),
        advisory=(_finding("ADVISORY", "adv-a"), _finding("ADVISORY", "adv-new")),
    )

    delta = compare_review_sessions(current, baseline)

    assert delta.status == "COMPLETE"
    assert {(item.state, item.finding.fingerprint) for item in delta.deterministic} == {
        ("PERSISTING", "det-a"),
        ("NEW", "det-new"),
        ("ABSENT_CURRENT", "det-old"),
    }
    assert {(item.state, item.finding.fingerprint) for item in delta.advisory} == {
        ("PERSISTING", "adv-a"),
        ("NEW", "adv-new"),
        ("ABSENT_CURRENT", "adv-old"),
    }
    assert "does not prove remediation" in delta.interpretation_note


def test_review_delta_refuses_cross_repository_comparison():
    baseline = _session("baseline", repository_identity="repo-a")
    current = _session("current", repository_identity="repo-b")

    delta = compare_review_sessions(current, baseline)

    assert delta.status == "IDENTITY_MISMATCH"
    assert delta.deterministic == ()
    assert delta.advisory == ()


def test_review_delta_warns_when_advisory_coverage_is_partial():
    baseline = _session(
        "baseline",
        sources=(SessionSource(source="open-code-review", status="COMPLETED", scope_status="MATCHED"),),
    )
    current = _session(
        "current",
        sources=(SessionSource(source="open-code-review", status="COMPLETED", scope_status="PARTIAL"),),
    )

    delta = compare_review_sessions(current, baseline)

    assert delta.status == "COMPLETE"
    assert "ABSENT_CURRENT findings require human interpretation" in (delta.message or "")
    assert "current:open-code-review:COMPLETED/PARTIAL" in (delta.message or "")


def test_review_session_round_trip_preserves_minimal_snapshot(tmp_path):
    session = _session(
        "session-1",
        deterministic=(_finding("DETERMINISTIC", "det-1"),),
        advisory=(_finding("ADVISORY", "adv-1"),),
        sources=(SessionSource(source="open-code-review", status="COMPLETED", scope_status="MATCHED"),),
    )
    path = tmp_path / "review-session.json"
    path.write_text(render_review_session_json(session), encoding="utf-8")

    loaded = load_review_session(path)

    assert loaded == session
    payload = loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["review_session"]["repository_identity"] == "repo-identity"


def test_review_delta_renderers_keep_absence_semantics_explicit():
    baseline = _session("baseline", advisory=(_finding("ADVISORY", "gone"),))
    current = _session("current")
    delta = compare_review_sessions(current, baseline)

    json_output = render_review_delta_json(delta)
    markdown = render_review_delta_markdown(delta)

    assert '"state": "ABSENT_CURRENT"' in json_output
    assert "ABSENT_CURRENT" in markdown
    assert "does not prove remediation" in markdown


def test_baseline_parse_failure_is_represented_as_gate_neutral_delta_error(tmp_path):
    current = _session("current")
    path = tmp_path / "broken.json"
    path.write_text("not-json", encoding="utf-8")

    try:
        load_review_session(path)
    except ValueError as error:
        delta = review_delta_error(current, path, error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("broken baseline unexpectedly loaded")

    assert delta.status == "ERROR"
    assert delta.current_session_id == "current"
    assert delta.baseline_session_id is None
    assert "ValueError" in (delta.message or "")


def test_build_review_session_captures_advisory_source_health_and_fingerprints(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    deterministic = Finding(
        rule_id="SEC-TEST-001",
        rule_version="1.0.0",
        title="Deterministic finding",
        message="bounded evidence",
        remediation="fix it",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        fingerprint="det-fingerprint",
        location=Location(path="src/app.py", start_line=1, end_line=1),
    )
    scan = ScanResult(
        manifest=ScanManifest(
            scan_id="scan-1",
            repository_path=repository.as_posix(),
            repository_digest="repo-digest",
            policy_digest="policy-digest",
            policy_name="test",
            started_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
            completed_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
        ),
        executions=(),
        findings=(deterministic,),
        waivers=(),
        decision=PolicyDecision(
            outcome=GateOutcome.BLOCK,
            reason_codes=("BLOCKING_FINDINGS",),
            blocking_fingerprints=("det-fingerprint",),
        ),
    )
    advisory_finding = AdvisoryFinding(
        finding_id="ADV-1",
        source="open-code-review",
        title="Possible bug",
        message="check this",
        category="bug",
        severity="high",
        confidence=None,
        fingerprint="adv-fingerprint",
        location=Location(path="src/app.py", start_line=1, end_line=1),
    )
    advisory_source = AdvisoryImport(
        input_name="ocr",
        source="open-code-review",
        source_format="ocr-json",
        findings=(advisory_finding,),
        status="COMPLETED",
        scope_status="PARTIAL",
        scope_message="one path was not selected",
    )
    review = UnifiedReviewResult(
        scan=scan,
        advisory_sources=(advisory_source,),
        advisory_findings=(advisory_finding,),
        correlations=(),
    )

    session = build_review_session(review)

    assert session.deterministic_findings[0].fingerprint == "det-fingerprint"
    assert session.advisory_findings[0].fingerprint == "adv-fingerprint"
    assert session.advisory_sources == (
        SessionSource(source="open-code-review", status="COMPLETED", scope_status="PARTIAL"),
    )
    assert session.repository_identity
    assert session.identity_basis == "local_path_hash"
