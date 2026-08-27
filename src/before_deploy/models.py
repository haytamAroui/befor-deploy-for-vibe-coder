"""Stable domain models for deterministic security scanning."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from json import dumps
from pathlib import Path
from typing import Any, Mapping, Sequence
from uuid import uuid4


class Severity(str, Enum):
    """Impact rating of a finding, independent from release policy."""

    BLOCKER = "BLOCKER"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(str, Enum):
    """Confidence in the detector's assertion."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Disposition(str, Enum):
    """Policy action for a finding."""

    BLOCK = "BLOCK"
    WAIVER_REQUIRED = "WAIVER_REQUIRED"
    WARN = "WARN"


class ExecutionStatus(str, Enum):
    """Status of an individual control execution."""

    COMPLETED = "COMPLETED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class GateOutcome(str, Enum):
    """Final deterministic release outcome."""

    PASS = "PASS"
    BLOCK = "BLOCK"
    WAIVER_REQUIRED = "WAIVER_REQUIRED"
    ERROR = "ERROR"
    NOT_EVALUATED = "NOT_EVALUATED"


class EvidenceKind(str, Enum):
    """Provenance category for a bounded, redaction-safe evidence signal."""

    REPOSITORY = "REPOSITORY"
    REQUIREMENT = "REQUIREMENT"
    INFRASTRUCTURE = "INFRASTRUCTURE"


class CoverageStatus(str, Enum):
    """Deterministic coverage state that cannot change a release outcome."""

    COVERED = "COVERED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_SELECTED = "NOT_SELECTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DECLARED_REVIEW_REQUIRED = "DECLARED_REVIEW_REQUIRED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Location:
    """A redaction-safe source location."""

    path: str
    start_line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True)
class Finding:
    """A normalized, redaction-safe security finding."""

    rule_id: str
    rule_version: str
    title: str
    message: str
    remediation: str
    severity: Severity
    confidence: Confidence
    fingerprint: str
    location: Location | None = None
    evidence: Mapping[str, str] = field(default_factory=dict)
    disposition: Disposition | None = None

    def with_disposition(self, disposition: Disposition) -> "Finding":
        """Return the finding after policy assigns its action."""
        return Finding(
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            title=self.title,
            message=self.message,
            remediation=self.remediation,
            severity=self.severity,
            confidence=self.confidence,
            fingerprint=self.fingerprint,
            location=self.location,
            evidence=self.evidence,
            disposition=disposition,
        )


@dataclass(frozen=True)
class ControlExecution:
    """A trace of a control adapter's execution and health."""

    control_id: str
    status: ExecutionStatus
    started_at: datetime
    completed_at: datetime
    control_version: str
    applicable: bool = True
    message: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanManifest:
    """Inputs and metadata required to reproduce a scan."""

    scan_id: str
    repository_path: str
    repository_digest: str
    policy_digest: str
    policy_name: str
    started_at: datetime
    completed_at: datetime | None = None
    git_revision: str | None = None
    scanned_file_count: int = 0
    excluded_file_count: int = 0
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Waiver:
    """A narrowly scoped acceptance of one exact normalized finding."""

    waiver_id: str
    finding_fingerprint: str
    rule_id: str
    repository_digest: str
    approved_by: str
    justification: str
    compensating_controls: str
    expires_at: datetime


@dataclass(frozen=True)
class PolicyDecision:
    """The only release authority produced by Sentinel."""

    outcome: GateOutcome
    reason_codes: tuple[str, ...]
    blocking_fingerprints: tuple[str, ...] = ()
    waiver_required_fingerprints: tuple[str, ...] = ()
    waived_fingerprints: tuple[str, ...] = ()
    advisory_fingerprints: tuple[str, ...] = ()
    error_control_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectProfile:
    """Deterministic, redaction-safe technology and coverage profile for one repository."""

    languages: tuple[str, ...]
    frameworks: tuple[str, ...]
    package_managers: tuple[str, ...]
    signals: Mapping[str, str]
    coverage_gaps: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceSignal:
    """A versioned, redaction-safe fact established from bounded repository evidence."""

    signal_id: str
    signal_version: str
    kind: EvidenceKind
    title: str
    location: Location
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilitySelection:
    """One approved capability selected by a deterministic plan with traceable provenance."""

    capability_id: str
    capability_version: str
    implementation_id: str
    kind: str
    rationale: str
    policy_name: str
    policy_digest: str
    catalog_digest: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageExpectation:
    """A security domain that should be assessed because of deterministic evidence."""

    domain: str
    rationale: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityAnalysisPlan:
    """Versioned, deterministic selection record; it is not a release decision."""

    plan_version: str
    profile_version: str
    catalog_version: str
    catalog_digest: str
    policy_name: str
    policy_digest: str
    evidence: tuple[EvidenceSignal, ...]
    control_selections: tuple[CapabilitySelection, ...]
    adapter_selections: tuple[CapabilitySelection, ...]
    skill_selections: tuple[CapabilitySelection, ...]
    coverage_expectations: tuple[CoverageExpectation, ...]
    exclusions: tuple[str, ...]


@dataclass(frozen=True)
class CoverageAssessment:
    """A transparent coverage state for one analysis domain."""

    domain: str
    status: CoverageStatus
    rationale: str
    capability_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageAudit:
    """Versioned coverage output that cannot modify the deterministic gate decision."""

    audit_version: str
    assessments: tuple[CoverageAssessment, ...]


@dataclass(frozen=True)
class ScanResult:
    """Complete scan output shared by policy and report writers."""

    manifest: ScanManifest
    executions: tuple[ControlExecution, ...]
    findings: tuple[Finding, ...]
    waivers: tuple[Waiver, ...]
    decision: PolicyDecision
    project_profile: ProjectProfile | None = None
    security_analysis_plan: SecurityAnalysisPlan | None = None
    coverage_audit: CoverageAudit | None = None


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def new_scan_id() -> str:
    """Create an opaque scan identifier without exposing repository metadata."""
    return str(uuid4())


def fingerprint_for(rule_id: str, location: Location | None, evidence: Mapping[str, str]) -> str:
    """Generate a stable fingerprint without serializing raw source or secrets."""
    payload = {
        "rule_id": rule_id,
        "location": to_primitive(location) if location else None,
        "evidence": dict(sorted(evidence.items())),
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def to_primitive(value: Any) -> Any:
    """Convert domain values into JSON-safe primitives."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Path):
        return value.as_posix()
    if is_dataclass(value):
        return {key: to_primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_primitive(item) for item in value]
    return value
