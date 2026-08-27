"""Canonical machine-readable report serialization."""

from __future__ import annotations

from json import dumps

from before_deploy.models import ScanResult, to_primitive


def render_json(result: ScanResult) -> str:
    """Render the complete redaction-safe scan result as stable JSON."""
    payload = {
        "schema_version": 1,
        "scan": to_primitive(result),
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
