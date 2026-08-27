"""Bounded Laravel Composer lockfile evidence without PHP or Composer execution."""

from __future__ import annotations

import json

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


class LaravelComposerLockfileControl:
    """Require a root composer.lock for one direct, static Laravel application shape."""

    control_id = "SEC-PHP-LARAVEL-COMPOSER-LOCK-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        root_files = {
            path.relative_to(context.repository_root).as_posix(): path
            for path in context.inventory.files
        }
        manifest_path = root_files.get("composer.json")
        if manifest_path is None or "artisan" not in root_files:
            return _not_applicable(
                self,
                started_at,
                "No root composer.json and artisan Laravel application shape was detected.",
            )
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except OSError:
            return _error_result(self, started_at, "COMPOSER_MANIFEST_UNREADABLE")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error_result(self, started_at, "COMPOSER_MANIFEST_INVALID")
        if not isinstance(manifest, dict):
            return _error_result(self, started_at, "COMPOSER_MANIFEST_INVALID")
        requirements = manifest.get("require")
        if requirements is None:
            return _not_applicable(
                self,
                started_at,
                "No direct supported Laravel framework requirement was detected in root composer.json.",
            )
        if not isinstance(requirements, dict):
            return _error_result(self, started_at, "COMPOSER_MANIFEST_INVALID")
        if "laravel/framework" not in requirements:
            return _not_applicable(
                self,
                started_at,
                "No direct supported Laravel framework requirement was detected in root composer.json.",
            )

        findings: tuple[Finding, ...] = ()
        if "composer.lock" not in root_files:
            location = Location(path="composer.json", start_line=1)
            evidence = {
                "ecosystem": "composer",
                "framework": "laravel",
                "issue": "composer_lock_missing",
            }
            findings = (
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="Laravel Composer dependency lockfile is missing",
                    message=(
                        "The root Laravel application shape declares the supported framework requirement but "
                        "has no root composer.lock file."
                    ),
                    remediation=(
                        "Generate and commit composer.lock through a reviewed dependency update workflow, "
                        "then use the locked dependency set in continuous integration."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    fingerprint=fingerprint_for(self.control_id, location, evidence),
                    location=location,
                    evidence=evidence,
                ),
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Inspected root Laravel Composer manifest and composer.lock presence.",
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
            message=f"Laravel Composer control error: {error_kind}",
            metadata={"error_kind": error_kind},
        )
    )
