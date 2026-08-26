"""Narrow native secret detection with redaction-safe evidence."""

from __future__ import annotations

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

_TEXT_SUFFIXES = {
    ".cfg",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".mjs",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "high_entropy_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|access[_-]?token)\b\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9_\-/+=]{24,})"
        ),
    ),
)


class SecretDetectionControl:
    """Detect a deliberately narrow set of high-confidence committed-secret patterns."""

    control_id = "SEC-SECRET-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        findings: list[Finding] = []
        for path in context.inventory.files:
            if not _is_text_candidate(path):
                continue
            relative = path.relative_to(context.repository_root).as_posix()
            text = _read_text(path)
            if text is None:
                continue
            for pattern_name, pattern in _PATTERNS:
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    secret_digest = sha256(match.group(0).encode("utf-8")).hexdigest()[:16]
                    location = Location(path=relative, start_line=line)
                    evidence = {"pattern": pattern_name, "match_digest": secret_digest}
                    findings.append(
                        Finding(
                            rule_id=self.control_id,
                            rule_version=self.control_version,
                            title="Likely committed secret",
                            message=(
                                "A high-confidence credential pattern was detected. The suspected value is "
                                "intentionally redacted from all Sentinel outputs."
                            ),
                            remediation=(
                                "Remove the value from the repository, rotate it with the issuing provider, "
                                "and load the replacement through an approved secret manager."
                            ),
                            severity=Severity.BLOCKER,
                            confidence=Confidence.HIGH,
                            fingerprint=fingerprint_for(self.control_id, location, evidence),
                            location=location,
                            evidence=evidence,
                        )
                    )
        completed_at = utc_now()
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                message=f"Scanned {len(context.inventory.files)} bounded repository files.",
            ),
            findings=tuple(findings),
        )


def _is_text_candidate(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in _TEXT_SUFFIXES


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    return raw.decode("utf-8", errors="replace")
