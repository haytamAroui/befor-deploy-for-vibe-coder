"""Bounded Rails Bundler lockfile evidence without Ruby, Bundler, or Rails execution."""

from __future__ import annotations

import re

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


_RAILS_GEM_DECLARATION = re.compile(
    r"^gem[ \t]+(?P<quote>['\"])rails(?P=quote)(?:[ \t]*,|[ \t]*$)", re.MULTILINE
)


class RailsGemfileLockfileControl:
    """Require a root Gemfile.lock for one direct conventional Rails application shape."""

    control_id = "SEC-RUBY-RAILS-GEMFILE-LOCK-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        root_files = {
            path.relative_to(context.repository_root).as_posix(): path
            for path in context.inventory.files
        }
        gemfile_path = root_files.get("Gemfile")
        if gemfile_path is None or "config/application.rb" not in root_files:
            return _not_applicable(
                self,
                started_at,
                "No root Gemfile and conventional config/application.rb Rails application shape was detected.",
            )
        try:
            gemfile = gemfile_path.read_text(encoding="utf-8")
        except OSError:
            return _error_result(self, started_at, "GEMFILE_UNREADABLE")
        except UnicodeDecodeError:
            return _error_result(self, started_at, "GEMFILE_INVALID_ENCODING")
        if _RAILS_GEM_DECLARATION.search(gemfile) is None:
            return _not_applicable(
                self,
                started_at,
                "No direct supported root Rails gem declaration was detected in Gemfile.",
            )

        findings: tuple[Finding, ...] = ()
        if "Gemfile.lock" not in root_files:
            location = Location(path="Gemfile", start_line=1)
            evidence = {
                "ecosystem": "bundler",
                "framework": "rails",
                "issue": "gemfile_lock_missing",
            }
            findings = (
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="Rails Bundler dependency lockfile is missing",
                    message=(
                        "The root conventional Rails application shape declares the supported framework gem but "
                        "has no root Gemfile.lock file."
                    ),
                    remediation=(
                        "Generate and commit Gemfile.lock through a reviewed dependency update workflow, then "
                        "use the locked dependency set in continuous integration."
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
            "Inspected root conventional Rails Gemfile and Gemfile.lock presence.",
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
            message=f"Rails Gemfile control error: {error_kind}",
            metadata={"error_kind": error_kind},
        )
    )
