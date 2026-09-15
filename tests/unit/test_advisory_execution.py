from __future__ import annotations

from hashlib import sha256

import pytest

from before_deploy.advisory_execution import (
    MODEL_IDENTITY_ATTESTED,
    MODEL_IDENTITY_UNATTESTED,
    AdvisoryExecutionBudget,
    AdvisoryExecutionDescriptor,
    AdvisoryExecutionParameter,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
    configuration_sha256,
    normalize_execution_descriptor,
    validate_raw_artifact,
)


def test_configuration_digest_is_order_independent_after_canonicalization():
    model = AdvisoryModelIdentity(
        status=MODEL_IDENTITY_ATTESTED,
        provider="example-ai",
        model="model-1",
    )
    left = AdvisoryExecutionDescriptor(
        implementation="example-cli",
        implementation_version="1.0.0",
        model=model,
        configuration=(
            AdvisoryExecutionParameter(name="zeta", value="last"),
            AdvisoryExecutionParameter(name="alpha", value="first"),
        ),
        budgets=(
            AdvisoryExecutionBudget(name="tokens", limit=1000, unit="tokens"),
            AdvisoryExecutionBudget(name="timeout", limit=30, unit="seconds"),
        ),
    )
    right = AdvisoryExecutionDescriptor(
        implementation="example-cli",
        implementation_version="1.0.0",
        model=model,
        configuration=tuple(reversed(left.configuration)),
        budgets=tuple(reversed(left.budgets)),
    )

    normalized = normalize_execution_descriptor(left)

    assert [item.name for item in normalized.configuration] == ["alpha", "zeta"]
    assert [item.name for item in normalized.budgets] == ["timeout", "tokens"]
    assert configuration_sha256(left) == configuration_sha256(right)


def test_unattested_model_requires_explicit_reason():
    descriptor = AdvisoryExecutionDescriptor(
        implementation="example-cli",
        implementation_version=None,
        model=AdvisoryModelIdentity(status=MODEL_IDENTITY_UNATTESTED),
    )

    with pytest.raises(ValueError, match="requires a reason"):
        normalize_execution_descriptor(descriptor)


def test_attested_model_requires_provider_and_model_name():
    descriptor = AdvisoryExecutionDescriptor(
        implementation="example-cli",
        implementation_version=None,
        model=AdvisoryModelIdentity(
            status=MODEL_IDENTITY_ATTESTED,
            provider="example-ai",
            model=None,
        ),
    )

    with pytest.raises(ValueError, match="requires provider and model"):
        normalize_execution_descriptor(descriptor)


def test_duplicate_configuration_or_budget_names_are_rejected():
    descriptor = AdvisoryExecutionDescriptor(
        implementation="example-cli",
        implementation_version=None,
        model=AdvisoryModelIdentity(
            status=MODEL_IDENTITY_UNATTESTED,
            reason="provider did not expose model identity",
        ),
        configuration=(
            AdvisoryExecutionParameter(name="mode", value="a"),
            AdvisoryExecutionParameter(name="mode", value="b"),
        ),
    )

    with pytest.raises(ValueError, match="configuration names must be unique"):
        normalize_execution_descriptor(descriptor)


def test_raw_artifact_validation_accepts_digest_only_metadata():
    raw = b'{"comments":[]}'
    artifact = AdvisoryRawArtifact(
        sha256=sha256(raw).hexdigest(),
        size_bytes=len(raw),
        media_type="application/json",
        schema="ocr-json",
    )

    validate_raw_artifact(artifact)


def test_raw_artifact_validation_rejects_invalid_digest():
    artifact = AdvisoryRawArtifact(
        sha256="not-a-sha",
        size_bytes=10,
        media_type="application/json",
    )

    with pytest.raises(ValueError, match="SHA-256"):
        validate_raw_artifact(artifact)
