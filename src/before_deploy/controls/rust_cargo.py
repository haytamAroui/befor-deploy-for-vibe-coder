"""Bounded Rust Cargo lockfile evidence without Cargo or Rust execution."""

from __future__ import annotations

import tomllib

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


class RustCargoLockfileControl:
    """Require a root Cargo.lock for one direct conventional Rust binary application shape."""

    control_id = "SEC-RUST-CARGO-LOCK-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        root_files = {
            path.relative_to(context.repository_root).as_posix(): path
            for path in context.inventory.files
        }
        manifest_path = root_files.get("Cargo.toml")
        if manifest_path is None or "src/main.rs" not in root_files:
            return _not_applicable(
                self,
                started_at,
                "No root Cargo.toml and conventional src/main.rs binary application shape was detected.",
            )
        try:
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except OSError:
            return _error_result(self, started_at, "CARGO_MANIFEST_UNREADABLE")
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return _error_result(self, started_at, "CARGO_MANIFEST_INVALID")

        dependencies = manifest.get("dependencies")
        if not isinstance(dependencies, dict) or not dependencies:
            return _completed(
                self,
                started_at,
                "No direct non-empty dependencies table was detected in root Cargo.toml.",
            )

        findings: tuple[Finding, ...] = ()
        if "Cargo.lock" not in root_files:
            location = Location(path="Cargo.toml", start_line=1)
            evidence = {
                "ecosystem": "cargo",
                "target": "conventional_binary",
                "issue": "cargo_lock_missing",
            }
            findings = (
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="Rust binary Cargo dependency lockfile is missing",
                    message=(
                        "The root conventional Rust binary shape declares direct dependencies but has no root "
                        "Cargo.lock file."
                    ),
                    remediation=(
                        "Generate and commit Cargo.lock through a reviewed dependency update workflow, then use "
                        "the locked dependency set in continuous integration."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    fingerprint=fingerprint_for(self.control_id, location, evidence),
                    location=location,
                    evidence=evidence,
                ),
            )
        return _completed(
            self,
            started_at,
            "Inspected root conventional Rust binary manifest and Cargo.lock presence.",
            findings=findings,
        )


def _completed(
    control,
    started_at,
    message: str,
    *,
    findings: tuple[Finding, ...] = (),
) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.COMPLETED,
            started_at=started_at,
            completed_at=utc_now(),
            message=message,
        ),
        findings=findings,
    )


def _not_applicable(control, started_at, message: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=False,
            message=message,
        )
    )


def _error_result(control, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Rust Cargo control error: {error_kind}",
            metadata={"error_kind": error_kind},
        )
    )
