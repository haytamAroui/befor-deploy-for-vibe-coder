"""Strict, expiry-bound waiver handling for deterministic policy evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from before_deploy.models import Finding, Waiver


def load_waivers(path: Path | None) -> tuple[Waiver, ...]:
    """Load narrowly scoped waiver records; absent files mean no waivers."""
    if path is None:
        return ()
    if not path.is_file():
        raise ValueError(f"Waiver file does not exist: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"Unable to load waiver file: {path}") from error
    if raw is None:
        return ()
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("Waiver file must be a mapping with schema_version: 1")
    records = raw.get("waivers", [])
    if not isinstance(records, list):
        raise ValueError("Waivers must be a list")

    waivers: list[Waiver] = []
    identifiers: set[str] = set()
    for record in records:
        waiver = _parse_waiver(record)
        if waiver.waiver_id in identifiers:
            raise ValueError(f"Duplicate waiver ID: {waiver.waiver_id}")
        identifiers.add(waiver.waiver_id)
        waivers.append(waiver)
    return tuple(waivers)


def matches_waiver(*, waiver: Waiver, finding: Finding, repository_digest: str) -> bool:
    """Match all waiver constraints exactly and reject expired records."""
    return (
        waiver.expires_at > datetime.now(timezone.utc)
        and waiver.finding_fingerprint == finding.fingerprint
        and waiver.rule_id == finding.rule_id
        and waiver.repository_digest == repository_digest
    )


def _parse_waiver(raw: Any) -> Waiver:
    if not isinstance(raw, dict):
        raise ValueError("Each waiver must be a mapping")
    required_strings = {
        "id": "waiver_id",
        "finding_fingerprint": "finding_fingerprint",
        "rule_id": "rule_id",
        "repository_digest": "repository_digest",
        "approved_by": "approved_by",
        "justification": "justification",
        "compensating_controls": "compensating_controls",
    }
    values: dict[str, str] = {}
    for source_key, target_key in required_strings.items():
        value = raw.get(source_key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Waiver field '{source_key}' must be a non-empty string")
        values[target_key] = value.strip()

    expires_raw = raw.get("expires_at")
    if not isinstance(expires_raw, str) or not expires_raw.strip():
        raise ValueError("Waiver field 'expires_at' must be a non-empty ISO 8601 timestamp")
    try:
        expires_at = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Waiver field 'expires_at' must be ISO 8601") from error
    if expires_at.tzinfo is None:
        raise ValueError("Waiver expiry must include a timezone")

    return Waiver(expires_at=expires_at.astimezone(timezone.utc), **values)
