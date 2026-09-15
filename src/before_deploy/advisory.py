"""Advisory review ingestion that is structurally separated from release authority."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from json import dumps, loads
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from before_deploy.advisory_execution import AdvisoryExecutionProvenance, AdvisoryRawArtifact
from before_deploy.models import Location, ScanResult

ADVISORY_AUTHORITY = "ADVISORY"
ADVISORY_GATE_EFFECT = "NONE"

_ALLOWED_CATEGORIES = {
    "bug",
    "security",
    "performance",
    "maintainability",
    "test",
    "style",
    "documentation",
    "other",
}
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass(frozen=True)
class AdvisoryFinding:
    """A normalized third-party or AI review finding with no release authority."""

    finding_id: str
    source: str
    title: str
    message: str
    category: str
    severity: str
    confidence: str | None
    fingerprint: str
    location: Location | None = None
    authority: str = ADVISORY_AUTHORITY
    gate_effect: str = ADVISORY_GATE_EFFECT


@dataclass(frozen=True)
class AdvisoryImport:
    """One imported advisory result plus content-free raw/execution lineage."""

    input_name: str
    source: str
    source_format: str
    findings: tuple[AdvisoryFinding, ...]
    status: str = "COMPLETED"
    message: str | None = None
    scope_status: str = "NOT_CHECKED"
    scope_message: str | None = None
    raw_artifact: AdvisoryRawArtifact | None = None
    execution: AdvisoryExecutionProvenance | None = None


def advisory_error_import(
    *,
    input_name: str,
    source: str,
    source_format: str,
    message: str,
    scope_status: str = "NOT_CHECKED",
    scope_message: str | None = None,
) -> AdvisoryImport:
    """Create a gate-neutral advisory source error for reporting."""
    return AdvisoryImport(
        input_name=input_name,
        source=source,
        source_format=source_format,
        findings=(),
        status="ERROR",
        message=message,
        scope_status=scope_status,
        scope_message=scope_message,
    )


@dataclass(frozen=True)
class ReviewCorrelation:
    """A source-location overlap, not a semantic proof or authority upgrade."""

    advisory_fingerprint: str
    deterministic_fingerprints: tuple[str, ...]
    relation: str = "LOCATION_OVERLAP"
    gate_effect: str = ADVISORY_GATE_EFFECT
    note: str = "Location overlap only; advisory authority is unchanged."


@dataclass(frozen=True)
class UnifiedReviewResult:
    """Combined developer view over deterministic and advisory review planes."""

    scan: ScanResult
    advisory_sources: tuple[AdvisoryImport, ...]
    advisory_findings: tuple[AdvisoryFinding, ...]
    correlations: tuple[ReviewCorrelation, ...]


def load_advisory_file(path: Path) -> AdvisoryImport:
    """Load canonical advisory JSON or OpenCodeReview JSON without importing raw code fields."""
    try:
        raw_bytes = path.read_bytes()
        payload = loads(raw_bytes.decode("utf-8"))
    except OSError:
        raise
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"Invalid advisory JSON in {path.name}: {error}") from error

    source, source_format, raw_findings = _extract_findings(payload)
    findings = tuple(
        _normalize_finding(item, source=source, index=index)
        for index, item in enumerate(raw_findings)
    )
    return AdvisoryImport(
        input_name=path.name,
        source=source,
        source_format=source_format,
        findings=findings,
        raw_artifact=AdvisoryRawArtifact(
            sha256=sha256(raw_bytes).hexdigest(),
            size_bytes=len(raw_bytes),
            media_type="application/json",
            schema=source_format,
        ),
    )


def build_unified_review(
    scan: ScanResult,
    advisory_sources: Iterable[AdvisoryImport],
) -> UnifiedReviewResult:
    """Combine views while preserving the deterministic PolicyDecision unchanged."""
    sources = tuple(advisory_sources)
    advisory_findings = tuple(finding for source in sources for finding in source.findings)
    correlations = tuple(
        correlation
        for finding in advisory_findings
        if (correlation := _correlate_by_location(finding, scan)) is not None
    )
    return UnifiedReviewResult(
        scan=scan,
        advisory_sources=sources,
        advisory_findings=advisory_findings,
        correlations=correlations,
    )


def _extract_findings(payload: Any) -> tuple[str, str, list[Mapping[str, Any]]]:
    if isinstance(payload, list):
        return "open-code-review", "ocr-json", _require_mapping_list(payload)

    if not isinstance(payload, Mapping):
        raise ValueError("Advisory JSON must be an object or a list of findings")

    if "findings" in payload:
        source = _canonical_source(payload.get("source"))
        return source, "before-deploy-advisory-v1", _require_mapping_list(payload["findings"])

    for key in ("comments", "results", "issues"):
        if key in payload:
            return "open-code-review", "ocr-json", _require_mapping_list(payload[key])

    raise ValueError("Advisory JSON contains no findings/comments/results/issues array")


def _canonical_source(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, Mapping):
        for key in ("provider", "name", "tool"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return "advisory-review"


def _require_mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("Advisory findings container must be an array")
    if not all(isinstance(item, Mapping) for item in value):
        raise ValueError("Every advisory finding must be an object")
    return list(value)


def _normalize_finding(item: Mapping[str, Any], *, source: str, index: int) -> AdvisoryFinding:
    message = _first_text(item, "message", "content", "description")
    if not message:
        raise ValueError(f"Advisory finding {index + 1} has no message/content")

    title = _first_text(item, "title", "rule_id", "name") or "Advisory code review finding"
    category = _normalize_enum(_first_text(item, "category"), _ALLOWED_CATEGORIES, "other")
    severity = _normalize_enum(_first_text(item, "severity"), _ALLOWED_SEVERITIES, "info")
    confidence = _confidence_text(item.get("confidence"))
    location = _normalize_location(item)
    fingerprint = _advisory_fingerprint(
        source=source,
        title=title,
        message=message,
        category=category,
        severity=severity,
        location=location,
    )
    finding_id = _first_text(item, "finding_id", "id") or f"ADV-{fingerprint[:12]}"

    return AdvisoryFinding(
        finding_id=finding_id,
        source=source,
        title=title,
        message=message,
        category=category,
        severity=severity,
        confidence=confidence,
        fingerprint=fingerprint,
        location=location,
    )


def _normalize_location(item: Mapping[str, Any]) -> Location | None:
    location_value = item.get("location")
    location = location_value if isinstance(location_value, Mapping) else {}
    raw_path = _first_text(location, "path") or _first_text(item, "path", "file")
    if not raw_path:
        return None

    path = _safe_relative_path(raw_path)
    start_line = _line_value(location.get("start_line", item.get("start_line")))
    end_line = _line_value(location.get("end_line", item.get("end_line")))
    if start_line is None and end_line is not None:
        start_line = end_line
    if end_line is None and start_line is not None:
        end_line = start_line
    if start_line is not None and end_line is not None and end_line < start_line:
        raise ValueError(f"Advisory finding has end_line before start_line for {path}")
    return Location(path=path, start_line=start_line, end_line=end_line)


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"Advisory finding path must be repository-relative: {value!r}")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError(f"Advisory finding path must not be an absolute drive path: {value!r}")
    return candidate.as_posix()


def _line_value(value: Any) -> int | None:
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, bool):
        raise ValueError("Advisory line number must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Advisory line number must be a positive integer") from error
    if parsed <= 0:
        raise ValueError("Advisory line number must be a positive integer")
    return parsed


def _normalize_enum(value: str, allowed: set[str], default: str) -> str:
    normalized = value.strip().lower() if value else ""
    return normalized if normalized in allowed else default


def _confidence_text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not 0 <= float(value) <= 1:
            raise ValueError("Advisory numeric confidence must be between 0 and 1")
        return f"{float(value):.3f}".rstrip("0").rstrip(".")
    text = str(value).strip()
    return text or None


def _first_text(item: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = item.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _advisory_fingerprint(
    *,
    source: str,
    title: str,
    message: str,
    category: str,
    severity: str,
    location: Location | None,
) -> str:
    payload = {
        "source": source,
        "title": title,
        "message": message,
        "category": category,
        "severity": severity,
        "location": None
        if location is None
        else {
            "path": location.path,
            "start_line": location.start_line,
            "end_line": location.end_line,
        },
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _correlate_by_location(finding: AdvisoryFinding, scan: ScanResult) -> ReviewCorrelation | None:
    if finding.location is None or finding.location.start_line is None:
        return None

    matches = []
    for deterministic in scan.findings:
        if deterministic.location is None or deterministic.location.start_line is None:
            continue
        if deterministic.location.path != finding.location.path:
            continue
        if _ranges_overlap(finding.location, deterministic.location):
            matches.append(deterministic.fingerprint)

    if not matches:
        return None
    return ReviewCorrelation(
        advisory_fingerprint=finding.fingerprint,
        deterministic_fingerprints=tuple(sorted(set(matches))),
    )


def _ranges_overlap(left: Location, right: Location) -> bool:
    left_start = left.start_line
    right_start = right.start_line
    if left_start is None or right_start is None:
        return False
    left_end = left.end_line or left_start
    right_end = right.end_line or right_start
    return left_start <= right_end and right_start <= left_end
