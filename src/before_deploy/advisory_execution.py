"""Attestable, gate-neutral provenance for advisory provider execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from json import dumps
from typing import Iterable

ADVISORY_EXECUTION_SCHEMA_VERSION = 1
ADVISORY_EXECUTION_AUTHORITY = "ADVISORY_EXECUTION"
ADVISORY_EXECUTION_GATE_EFFECT = "NONE"
MODEL_IDENTITY_ATTESTED = "ATTESTED"
MODEL_IDENTITY_UNATTESTED = "UNATTESTED"


@dataclass(frozen=True)
class AdvisoryRawArtifact:
    """Content-free digest of raw provider output used for normalization."""

    sha256: str
    size_bytes: int
    media_type: str
    schema: str | None = None


@dataclass(frozen=True)
class AdvisoryModelIdentity:
    """Provider-declared model identity with an explicit attestation state."""

    status: str
    provider: str | None = None
    model: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class AdvisoryExecutionParameter:
    """One redaction-safe provider execution configuration parameter."""

    name: str
    value: str


@dataclass(frozen=True)
class AdvisoryExecutionBudget:
    """One provider-declared bounded execution resource."""

    name: str
    limit: int
    unit: str


@dataclass(frozen=True)
class AdvisoryExecutionDescriptor:
    """Provider-declared execution identity and redaction-safe configuration."""

    implementation: str
    implementation_version: str | None
    model: AdvisoryModelIdentity
    configuration: tuple[AdvisoryExecutionParameter, ...] = ()
    budgets: tuple[AdvisoryExecutionBudget, ...] = ()


@dataclass(frozen=True)
class AdvisoryExecutionProvenance:
    """Runtime-observed lineage from deterministic context to normalized advisory output."""

    schema_version: int
    provider_id: str
    implementation: str
    implementation_version: str | None
    model: AdvisoryModelIdentity
    configuration: tuple[AdvisoryExecutionParameter, ...]
    configuration_sha256: str
    budgets: tuple[AdvisoryExecutionBudget, ...]
    context_sha256: str
    context_selected_files: int
    context_selected_bytes: int
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    raw_output: AdvisoryRawArtifact | None
    normalized_output_sha256: str
    result_status: str
    authority: str = ADVISORY_EXECUTION_AUTHORITY
    gate_effect: str = ADVISORY_EXECUTION_GATE_EFFECT


def normalize_execution_descriptor(
    descriptor: AdvisoryExecutionDescriptor,
) -> AdvisoryExecutionDescriptor:
    """Validate and canonicalize provider-declared execution metadata."""
    implementation = _nonempty_text(descriptor.implementation, "implementation")
    version = _optional_text(descriptor.implementation_version, "implementation_version")
    model = _validate_model(descriptor.model)
    configuration = tuple(sorted(descriptor.configuration, key=lambda item: item.name))
    budgets = tuple(sorted(descriptor.budgets, key=lambda item: item.name))

    _validate_unique_names((item.name for item in configuration), "configuration")
    _validate_unique_names((item.name for item in budgets), "budget")
    for item in configuration:
        _nonempty_text(item.name, "configuration name")
        _nonempty_text(item.value, f"configuration value for {item.name!r}")
        if len(item.name) > 100 or len(item.value) > 500:
            raise ValueError("Advisory execution configuration metadata is too large")
    for item in budgets:
        _nonempty_text(item.name, "budget name")
        _nonempty_text(item.unit, f"budget unit for {item.name!r}")
        if item.limit <= 0:
            raise ValueError(f"Advisory execution budget {item.name!r} must be positive")

    return AdvisoryExecutionDescriptor(
        implementation=implementation,
        implementation_version=version,
        model=model,
        configuration=configuration,
        budgets=budgets,
    )


def configuration_sha256(descriptor: AdvisoryExecutionDescriptor) -> str:
    """Hash only canonical redaction-safe provider configuration parameters."""
    normalized = normalize_execution_descriptor(descriptor)
    payload = [
        {"name": item.name, "value": item.value} for item in normalized.configuration
    ]
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def validate_raw_artifact(artifact: AdvisoryRawArtifact) -> None:
    """Validate that an artifact digest is structurally safe to expose in reports."""
    valid_sha = len(artifact.sha256) == 64 and all(
        character in "0123456789abcdef" for character in artifact.sha256
    )
    if not valid_sha:
        raise ValueError("Advisory raw artifact SHA-256 must be 64 lowercase hex characters")
    if artifact.size_bytes < 0:
        raise ValueError("Advisory raw artifact size must not be negative")
    _nonempty_text(artifact.media_type, "raw artifact media_type")
    _optional_text(artifact.schema, "raw artifact schema")


def _validate_model(model: AdvisoryModelIdentity) -> AdvisoryModelIdentity:
    if model.status not in {MODEL_IDENTITY_ATTESTED, MODEL_IDENTITY_UNATTESTED}:
        raise ValueError("Advisory model identity status must be ATTESTED or UNATTESTED")
    provider = _optional_text(model.provider, "model provider")
    name = _optional_text(model.model, "model name")
    reason = _optional_text(model.reason, "model identity reason")
    if model.status == MODEL_IDENTITY_ATTESTED and (provider is None or name is None):
        raise ValueError("ATTESTED advisory model identity requires provider and model")
    if model.status == MODEL_IDENTITY_UNATTESTED and reason is None:
        raise ValueError("UNATTESTED advisory model identity requires a reason")
    return AdvisoryModelIdentity(status=model.status, provider=provider, model=name, reason=reason)


def _validate_unique_names(names: Iterable[str], label: str) -> None:
    values = list(names)
    if len(values) != len(set(values)):
        raise ValueError(f"Advisory execution {label} names must be unique")


def _nonempty_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Advisory execution {label} must be non-empty text")
    return value.strip()


def _optional_text(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Advisory execution {label} must be non-empty text when supplied")
    return value.strip()
