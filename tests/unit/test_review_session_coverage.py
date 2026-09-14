from before_deploy.review_session import ReviewSession, SessionSource, compare_review_sessions


def _session(
    session_id: str,
    *,
    policy_digest: str = "policy-a",
    sources: tuple[SessionSource, ...] = (),
) -> ReviewSession:
    return ReviewSession(
        session_id=session_id,
        repository_identity="same-repository",
        identity_basis="git_root_commits",
        git_revision="abc123",
        policy_digest=policy_digest,
        deterministic_findings=(),
        advisory_findings=(),
        advisory_sources=sources,
    )


def test_policy_change_warns_against_interpreting_absence_as_remediation():
    baseline = _session("baseline", policy_digest="policy-a")
    current = _session("current", policy_digest="policy-b")

    delta = compare_review_sessions(current, baseline)

    assert delta.status == "COMPLETE"
    assert "policy digest changed" in (delta.message or "")
    assert "deterministic ABSENT_CURRENT" in (delta.message or "")


def test_advisory_source_set_change_is_visible_even_when_remaining_sources_are_healthy():
    baseline = _session(
        "baseline",
        sources=(
            SessionSource(
                source="open-code-review",
                status="COMPLETED",
                scope_status="MATCHED",
            ),
        ),
    )
    current = _session("current", sources=())

    delta = compare_review_sessions(current, baseline)

    assert delta.status == "COMPLETE"
    assert "advisory source set changed" in (delta.message or "")
    assert "provider that was not run" in (delta.message or "")
