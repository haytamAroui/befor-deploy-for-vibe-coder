"""Bounded, offline Go dependency-vulnerability snapshot control."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import (
    Confidence,
    ControlExecution,
    ExecutionStatus,
    Finding,
    Location,
    Severity,
    fingerprint_for,
    utc_now,
)

_MAX_SNAPSHOT_BYTES = 100_000
_SINGLE_REQUIRE_DIRECTIVE = re.compile(r"^\s*require\s+(?!\()(?P<body>.+?)\s*$", re.MULTILINE)
_REQUIRE_BLOCK = re.compile(r"^\s*require\s*\((?P<body>.*?)^\s*\)", re.MULTILINE | re.DOTALL)
_MODULE_LINE = re.compile(r"^\s*(?P<module>\S+)\s+(?P<version>\S+)\s*$")
_REPLACE_DIRECTIVE = re.compile(r"^\s*replace\b", re.MULTILINE)
_SEMVER = re.compile(r"^v(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)$")
_ADVISORY_ID = re.compile(r"^GO-\d{4}-\d{4,}$")
_MODULE_NAME = re.compile(r"^[A-Za-z0-9._~+\-/]+$")
_SNAPSHOT_ID = re.compile(r"^[A-Za-z0-9._-]+$")
BUILTIN_SNAPSHOT_PATH = Path(__file__).with_name("data") / "go_vulnerability_snapshot.json"
BUILTIN_SNAPSHOT_SHA256 = "f9ad184e4f959eda8c94e2efa27f36684c8ad000fc4386a9640c174df0e62339"


class GoVulnerabilitySnapshotControl:
    """Compare direct root-module requirements to a tiny reviewed offline advisory snapshot.

    This control neither invokes govulncheck nor contacts a vulnerability database. It records only
    a bounded advisory ID, module, declared version, and fixed version. Source reachability,
    indirect dependencies, replacement directives, build tags, and live database freshness remain
    intentionally out of scope.
    """

    control_id = "SEC-GO-VULN-001"
    control_version = "0.2.0"

    def __init__(
        self,
        snapshot_path: Path = BUILTIN_SNAPSHOT_PATH,
        expected_sha256: str = BUILTIN_SNAPSHOT_SHA256,
    ) -> None:
        self._snapshot_path = snapshot_path
        self._expected_sha256 = expected_sha256

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        root_files = {
            path.relative_to(context.repository_root).as_posix(): path
            for path in context.inventory.files
        }
        module_path = root_files.get("go.mod")
        if module_path is None:
            return _not_applicable(
                self,
                started_at,
                "No root go.mod manifest was detected for the offline Go vulnerability snapshot check.",
            )
        try:
            module_text = module_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return _error_result(self, started_at, "MODULE_MANIFEST_UNREADABLE")
        if _REPLACE_DIRECTIVE.search(_without_comments(module_text)):
            return _error_result(self, started_at, "REPLACE_DIRECTIVE_UNSUPPORTED")
        try:
            requirements = _direct_requirements(module_text)
        except ValueError:
            return _error_result(self, started_at, "INVALID_MODULE_REQUIREMENTS")
        try:
            snapshot = _load_snapshot(self._snapshot_path, self._expected_sha256)
        except ValueError as error:
            return _error_result(self, started_at, str(error))

        findings: list[Finding] = []
        for advisory in snapshot:
            version = requirements.get(advisory["module"])
            if version is None:
                continue
            try:
                affected = _is_before(version, advisory["affected_before"])
            except ValueError:
                return _error_result(self, started_at, "UNSUPPORTED_MODULE_VERSION")
            if not affected:
                continue
            evidence = {
                "advisory_id": advisory["id"],
                "ecosystem": "go",
                "fixed_version": advisory["fixed_version"],
                "module": advisory["module"],
                "module_version": version,
                "snapshot_id": advisory["snapshot_id"],
            }
            location = Location(path="go.mod", start_line=1)
            findings.append(
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title=f"Known Go dependency vulnerability: {advisory['id']}",
                    message=(
                        f"Root go.mod declares {advisory['module']} {version}, which is listed as affected "
                        f"by the reviewed offline snapshot until {advisory['affected_before']}. Source "
                        "reachability and raw advisory text are intentionally not retained."
                    ),
                    remediation=(
                        f"Upgrade {advisory['module']} to {advisory['fixed_version']} or a later reviewed "
                        "version, then regenerate and review go.sum."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    fingerprint=fingerprint_for(self.control_id, location, evidence),
                    location=location,
                    evidence=evidence,
                )
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    "Compared direct root go.mod requirements to the pinned reviewed offline Go "
                    f"vulnerability snapshot; normalized {len(findings)} affected dependency record(s)."
                ),
                metadata={
                    "evidence_source": "packaged_offline_go_vulnerability_snapshot",
                    "snapshot_sha256": self._expected_sha256,
                    "snapshot_id": snapshot[0]["snapshot_id"] if snapshot else "none",
                },
            ),
            findings=tuple(findings),
        )


def _load_snapshot(path: Path, expected_sha256: str) -> tuple[dict[str, str], ...]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("INVALID_EXPECTED_SNAPSHOT_DIGEST")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError("SNAPSHOT_UNREADABLE") from error
    if len(raw) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("SNAPSHOT_TOO_LARGE")
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("SNAPSHOT_DIGEST_MISMATCH")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("INVALID_SNAPSHOT") from error
    if not isinstance(parsed, dict) or set(parsed) != {"schema_version", "snapshot_id", "advisories"}:
        raise ValueError("INVALID_SNAPSHOT_SHAPE")
    if parsed.get("schema_version") != 1:
        raise ValueError("UNSUPPORTED_SNAPSHOT_SCHEMA")
    snapshot_id = parsed.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not _SNAPSHOT_ID.fullmatch(snapshot_id):
        raise ValueError("INVALID_SNAPSHOT_ID")
    raw_advisories = parsed.get("advisories")
    if not isinstance(raw_advisories, list) or not raw_advisories:
        raise ValueError("INVALID_SNAPSHOT_ADVISORIES")
    advisories: list[dict[str, str]] = []
    advisory_ids: set[str] = set()
    modules: set[str] = set()
    for raw_advisory in raw_advisories:
        if not isinstance(raw_advisory, dict) or set(raw_advisory) != {
            "id",
            "module",
            "affected_before",
            "fixed_version",
        }:
            raise ValueError("INVALID_SNAPSHOT_ADVISORY")
        advisory_id = raw_advisory.get("id")
        module = raw_advisory.get("module")
        affected_before = raw_advisory.get("affected_before")
        fixed_version = raw_advisory.get("fixed_version")
        if not isinstance(advisory_id, str) or not _ADVISORY_ID.fullmatch(advisory_id):
            raise ValueError("INVALID_SNAPSHOT_ADVISORY_ID")
        if not isinstance(module, str) or not _MODULE_NAME.fullmatch(module):
            raise ValueError("INVALID_SNAPSHOT_MODULE")
        if not isinstance(affected_before, str) or not _SEMVER.fullmatch(affected_before):
            raise ValueError("INVALID_SNAPSHOT_AFFECTED_VERSION")
        if not isinstance(fixed_version, str) or not _SEMVER.fullmatch(fixed_version):
            raise ValueError("INVALID_SNAPSHOT_FIXED_VERSION")
        if _version_tuple(fixed_version) != _version_tuple(affected_before):
            raise ValueError("SNAPSHOT_FIX_BOUNDARY_MISMATCH")
        if advisory_id in advisory_ids or module in modules:
            raise ValueError("DUPLICATE_SNAPSHOT_ADVISORY")
        advisory_ids.add(advisory_id)
        modules.add(module)
        advisories.append(
            {
                "id": advisory_id,
                "module": module,
                "affected_before": affected_before,
                "fixed_version": fixed_version,
                "snapshot_id": snapshot_id,
            }
        )
    return tuple(sorted(advisories, key=lambda item: (item["module"], item["id"])))


def _direct_requirements(module_text: str) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for directive in _SINGLE_REQUIRE_DIRECTIVE.finditer(module_text):
        line, _, comment = directive.group("body").partition("//")
        match = _MODULE_LINE.fullmatch(line.rstrip())
        if match is None:
            raise ValueError("Invalid require directive")
        if comment.strip() != "indirect":
            _add_requirement(requirements, match.group("module"), match.group("version"))
    for block in _REQUIRE_BLOCK.finditer(module_text):
        for raw_line in block.group("body").splitlines():
            line, _, comment = raw_line.partition("//")
            line = line.rstrip()
            if not line.strip():
                continue
            match = _MODULE_LINE.fullmatch(line)
            if match is None:
                raise ValueError("Invalid require block line")
            if comment.strip() == "indirect":
                continue
            _add_requirement(requirements, match.group("module"), match.group("version"))
    return requirements


def _add_requirement(requirements: dict[str, str], module: str, version: str) -> None:
    if not _MODULE_NAME.fullmatch(module) or not _SEMVER.fullmatch(version):
        raise ValueError("Unsupported module requirement")
    previous = requirements.get(module)
    if previous is not None and previous != version:
        raise ValueError("Duplicate module requirement")
    requirements[module] = version


def _without_comments(module_text: str) -> str:
    return "\n".join(line.split("//", 1)[0].rstrip() for line in module_text.splitlines())


def _is_before(version: str, boundary: str) -> bool:
    return _version_tuple(version) < _version_tuple(boundary)


def _version_tuple(version: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(version)
    if match is None:
        raise ValueError("Unsupported semantic version")
    return tuple(int(match.group(part)) for part in ("major", "minor", "patch"))


def _not_applicable(
    control: GoVulnerabilitySnapshotControl, started_at, message: str
) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=False,
            message=message,
            metadata={"evidence_source": "packaged_offline_go_vulnerability_snapshot"},
        )
    )


def _error_result(
    control: GoVulnerabilitySnapshotControl, started_at, error_kind: str
) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Offline Go vulnerability evidence error: {error_kind}",
            metadata={
                "evidence_source": "packaged_offline_go_vulnerability_snapshot",
                "error_kind": error_kind,
            },
        )
    )
