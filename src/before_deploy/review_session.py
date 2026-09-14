"""Persistent, gate-neutral review sessions and deterministic finding deltas."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps, loads
from pathlib import Path
from subprocess import DEVNULL, PIPE, TimeoutExpired, run
from typing import Any, Mapping

from before_deploy.advisory import UnifiedReviewResult
from before_deploy.models import Location, to_primitive

SESSION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SessionFinding:
    """Redaction-safe finding identity retained across review runs."""

    plane: str
    fingerprint: str
    title: str
    severity: str
    source: str
    location: Location | None = None


@dataclass(frozen=True)
class SessionSource:
    """Advisory-source health retained so absence is not mistaken for a fix."""

    source: str
    status: str
    scope_status: str


@dataclass(frozen=True)
class ReviewSession:
    """Portable snapshot used only for longitudinal review diagnostics."""

    session_id: str
    repository_identity: str
    identity_basis: str
    git_revision: str | None
    policy_digest: str
    deterministic_findings: tuple[SessionFinding, ...]
    advisory_findings: tuple[SessionFinding, ...]
    advisory_sources: tuple[SessionSource, ...]


@dataclass(frozen=True)
class FindingDelta:
    """One lifecycle observation between a baseline and current review."""

    state: str
    finding: SessionFinding


@dataclass(frozen=True)
class ReviewDelta:
    """Gate-neutral comparison of two review sessions."""

    status: str
    current_session_id: str
    baseline_session_id: str | None
    deterministic: tuple[FindingDelta, ...] = ()
    advisory: tuple[FindingDelta, ...] = ()
    message: str | None = None
    interpretation_note: str = (
        "ABSENT_CURRENT means the fingerprint was not reported in the current run; "
        "it does not prove remediation."
    )


def build_review_session(review: UnifiedReviewResult) -> ReviewSession:
    """Freeze a minimal longitudinal snapshot without changing review authority."""
    identity, basis = _repository_identity(Path(review.scan.manifest.repository_path))
    deterministic = tuple(
        SessionFinding(
            plane="DETERMINISTIC",
            fingerprint=finding.fingerprint,
            title=finding.title,
            severity=finding.severity.value,
            source=finding.rule_id,
            location=finding.location,
        )
        for finding in review.scan.findings
    )
    advisory = tuple(
        SessionFinding(
            plane="ADVISORY",
            fingerprint=finding.fingerprint,
            title=finding.title,
            severity=finding.severity,
            source=finding.source,
            location=finding.location,
        )
        for finding in review.advisory_findings
    )
    sources = tuple(
        SessionSource(
            source=source.source,
            status=source.status,
            scope_status=source.scope_status,
        )
        for source in review.advisory_sources
    )
    return ReviewSession(
        session_id=review.scan.manifest.scan_id,
        repository_identity=identity,
        identity_basis=basis,
        git_revision=review.scan.manifest.git_revision,
        policy_digest=review.scan.manifest.policy_digest,
        deterministic_findings=deterministic,
        advisory_findings=advisory,
        advisory_sources=sources,
    )


def load_review_session(path: Path) -> ReviewSession:
    """Load and validate a Before Deploy review-session artifact."""
    try:
        payload = loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise
    except ValueError as error:
        raise ValueError("Review session is not valid JSON") from error
    if not isinstance(payload, Mapping) or payload.get("schema_version") != SESSION_SCHEMA_VERSION:
        raise ValueError("Unsupported review-session schema")
    raw = payload.get("review_session")
    if not isinstance(raw, Mapping):
        raise ValueError("Review session payload is missing")
    return ReviewSession(
        session_id=_required_text(raw, "session_id"),
        repository_identity=_required_text(raw, "repository_identity"),
        identity_basis=_required_text(raw, "identity_basis"),
        git_revision=_optional_text(raw.get("git_revision")),
        policy_digest=_required_text(raw, "policy_digest"),
        deterministic_findings=_load_findings(raw.get("deterministic_findings"), "DETERMINISTIC"),
        advisory_findings=_load_findings(raw.get("advisory_findings"), "ADVISORY"),
        advisory_sources=_load_sources(raw.get("advisory_sources")),
    )


def compare_review_sessions(current: ReviewSession, baseline: ReviewSession) -> ReviewDelta:
    """Compare stable fingerprints without interpreting disappearance as remediation."""
    if current.repository_identity != baseline.repository_identity:
        return ReviewDelta(
            status="IDENTITY_MISMATCH",
            current_session_id=current.session_id,
            baseline_session_id=baseline.session_id,
            message="Baseline belongs to a different repository identity; no lifecycle comparison was made.",
        )
    return ReviewDelta(
        status="COMPLETE",
        current_session_id=current.session_id,
        baseline_session_id=baseline.session_id,
        deterministic=_compare_plane(current.deterministic_findings, baseline.deterministic_findings),
        advisory=_compare_plane(current.advisory_findings, baseline.advisory_findings),
        message=_coverage_message(current, baseline),
    )


def review_delta_error(current: ReviewSession, baseline_path: Path, error: Exception) -> ReviewDelta:
    """Represent baseline failure without allowing it to affect the release exit code."""
    return ReviewDelta(
        status="ERROR",
        current_session_id=current.session_id,
        baseline_session_id=None,
        message=(
            f"Baseline session {baseline_path.name!r} could not be compared: "
            f"{type(error).__name__}"
        ),
    )


def render_review_session_json(session: ReviewSession) -> str:
    return dumps(
        {"schema_version": SESSION_SCHEMA_VERSION, "review_session": to_primitive(session)},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_review_delta_json(delta: ReviewDelta) -> str:
    return dumps(
        {"schema_version": 1, "review_delta": to_primitive(delta)},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def render_review_delta_markdown(delta: ReviewDelta) -> str:
    lines = [
        "# Before Deploy Review Delta",
        "",
        f"- Status: `{delta.status}`",
        f"- Current session: `{delta.current_session_id}`",
    ]
    if delta.baseline_session_id:
        lines.append(f"- Baseline session: `{delta.baseline_session_id}`")
    if delta.message:
        lines.append(f"- Note: {delta.message}")
    lines.extend(["", f"> {delta.interpretation_note}", ""])
    if delta.status != "COMPLETE":
        return "\n".join(lines).rstrip() + "\n"

    for title, items in (("Deterministic", delta.deterministic), ("Advisory", delta.advisory)):
        counts = {
            state: sum(item.state == state for item in items)
            for state in ("NEW", "PERSISTING", "ABSENT_CURRENT")
        }
        lines.extend(
            [
                f"## {title}",
                "",
                f"- NEW: **{counts['NEW']}**",
                f"- PERSISTING: **{counts['PERSISTING']}**",
                f"- ABSENT_CURRENT: **{counts['ABSENT_CURRENT']}**",
                "",
            ]
        )
        for item in items:
            location = _location_text(item.finding.location)
            suffix = f" at `{location}`" if location else ""
            lines.append(
                f"- `{item.state}` [{item.finding.severity}] {item.finding.title}{suffix} "
                f"(`{item.finding.source}`)"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _compare_plane(
    current: tuple[SessionFinding, ...],
    baseline: tuple[SessionFinding, ...],
) -> tuple[FindingDelta, ...]:
    current_by_id = {finding.fingerprint: finding for finding in current}
    baseline_by_id = {finding.fingerprint: finding for finding in baseline}
    items: list[FindingDelta] = []
    for fingerprint in sorted(current_by_id):
        state = "PERSISTING" if fingerprint in baseline_by_id else "NEW"
        items.append(FindingDelta(state=state, finding=current_by_id[fingerprint]))
    for fingerprint in sorted(set(baseline_by_id) - set(current_by_id)):
        items.append(FindingDelta(state="ABSENT_CURRENT", finding=baseline_by_id[fingerprint]))
    return tuple(items)


def _coverage_message(current: ReviewSession, baseline: ReviewSession) -> str | None:
    notes: list[str] = []
    if current.policy_digest != baseline.policy_digest:
        notes.append(
            "The deterministic policy digest changed between sessions; deterministic "
            "ABSENT_CURRENT findings may reflect policy/control selection changes."
        )

    current_source_names = {source.source for source in current.advisory_sources}
    baseline_source_names = {source.source for source in baseline.advisory_sources}
    if current_source_names != baseline_source_names:
        notes.append(
            "The advisory source set changed between sessions; advisory ABSENT_CURRENT "
            "findings may reflect a provider that was not run."
        )

    degraded = [
        f"current:{source.source}:{source.status}/{source.scope_status}"
        for source in current.advisory_sources
        if source.status != "COMPLETED" or source.scope_status not in {"MATCHED", "NOT_CHECKED"}
    ]
    degraded.extend(
        f"baseline:{source.source}:{source.status}/{source.scope_status}"
        for source in baseline.advisory_sources
        if source.status != "COMPLETED" or source.scope_status not in {"MATCHED", "NOT_CHECKED"}
    )
    if degraded:
        notes.append(
            "Advisory coverage differs or is incomplete for one or more sources; "
            "ABSENT_CURRENT findings require human interpretation. States: "
            + ", ".join(degraded)
        )
    return " ".join(notes) or None


def _repository_identity(repository: Path) -> tuple[str, str]:
    roots = _git_root_commits(repository)
    if roots:
        material = "git-roots\0" + "\0".join(sorted(roots))
        return sha256(material.encode("utf-8")).hexdigest(), "git_root_commits"
    material = "local-path\0" + repository.resolve().as_posix()
    return sha256(material.encode("utf-8")).hexdigest(), "local_path_hash"


def _git_root_commits(repository: Path) -> tuple[str, ...]:
    try:
        completed = run(
            ["git", "-C", str(repository), "rev-list", "--max-parents=0", "HEAD"],
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, TimeoutExpired):
        return ()
    if completed.returncode != 0:
        return ()
    return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())


def _load_findings(value: Any, expected_plane: str) -> tuple[SessionFinding, ...]:
    if not isinstance(value, list):
        raise ValueError("Review session finding collection must be an array")
    findings = []
    for item in value:
        if not isinstance(item, Mapping) or item.get("plane") != expected_plane:
            raise ValueError("Review session finding has an invalid plane")
        location = _load_location(item.get("location"))
        findings.append(
            SessionFinding(
                plane=expected_plane,
                fingerprint=_required_text(item, "fingerprint"),
                title=_required_text(item, "title"),
                severity=_required_text(item, "severity"),
                source=_required_text(item, "source"),
                location=location,
            )
        )
    return tuple(findings)


def _load_sources(value: Any) -> tuple[SessionSource, ...]:
    if not isinstance(value, list):
        raise ValueError("Review session advisory_sources must be an array")
    sources = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("Review session advisory source must be an object")
        sources.append(
            SessionSource(
                source=_required_text(item, "source"),
                status=_required_text(item, "status"),
                scope_status=_required_text(item, "scope_status"),
            )
        )
    return tuple(sources)


def _load_location(value: Any) -> Location | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("Review session location must be an object")
    path = _required_text(value, "path")
    start = _optional_int(value.get("start_line"))
    end = _optional_int(value.get("end_line"))
    return Location(path=path, start_line=start, end_line=end)


def _required_text(item: Mapping[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Review session field {name!r} must be non-empty text")
    return value


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Review session optional text field is invalid")
    return value or None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("Review session line number must be a positive integer")
    return value


def _location_text(location: Location | None) -> str:
    if location is None:
        return ""
    if location.start_line is None:
        return location.path
    if location.end_line is None or location.end_line == location.start_line:
        return f"{location.path}:{location.start_line}"
    return f"{location.path}:{location.start_line}-{location.end_line}"
