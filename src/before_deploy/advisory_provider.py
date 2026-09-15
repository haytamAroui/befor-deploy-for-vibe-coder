"""Provider runtime for non-authoritative advisory review execution."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from before_deploy.advisory import (
    ADVISORY_AUTHORITY,
    ADVISORY_GATE_EFFECT,
    AdvisoryImport,
    advisory_error_import,
)
from before_deploy.advisory_context import (
    DEFAULT_MAX_CONTEXT_BYTES,
    AdvisoryContext,
    build_advisory_context,
    context_summary,
    validate_advisory_context,
)


@dataclass(frozen=True)
class AdvisoryProviderIdentity:
    """Stable provider identity used to normalize provider runtime output."""

    provider_id: str
    input_name: str
    source: str
    source_format: str


@dataclass(frozen=True)
class AdvisoryProviderRequest:
    """Provider-independent repository review request with deterministic context bounds."""

    repository: Path
    max_file_bytes: int = 1_000_000
    max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES
    from_ref: str | None = None
    to_ref: str | None = None
    commit: str | None = None
    context: AdvisoryContext | None = None


class AdvisoryProvider(Protocol):
    """An advisory discovery provider with no deterministic release authority."""

    @property
    def identity(self) -> AdvisoryProviderIdentity: ...

    def review(self, request: AdvisoryProviderRequest) -> AdvisoryImport: ...


def execute_advisory_provider(
    provider: AdvisoryProvider,
    request: AdvisoryProviderRequest,
) -> AdvisoryImport:
    """Execute one provider only after deterministic context validation."""
    identity = provider.identity
    identity_error = _validate_identity(identity)
    if identity_error is not None:
        return advisory_error_import(
            input_name="advisory-provider",
            source="advisory-provider",
            source_format="unknown",
            message=identity_error,
        )

    request_error = _validate_request(request)
    if request_error is not None:
        return _provider_error(identity, request_error)

    resolved_request = replace(request, repository=request.repository.resolve())
    try:
        context = resolved_request.context or build_advisory_context(
            resolved_request.repository,
            max_file_bytes=resolved_request.max_file_bytes,
            max_context_bytes=resolved_request.max_context_bytes,
            from_ref=resolved_request.from_ref,
            to_ref=resolved_request.to_ref,
            commit=resolved_request.commit,
        )
        validate_advisory_context(context)
        _validate_context_binding(resolved_request, context)
        resolved_request = replace(resolved_request, context=context)
    except (OSError, ValueError) as error:
        return _provider_error(
            identity,
            f"Advisory context preparation failed: {type(error).__name__}",
        )

    try:
        imported = provider.review(resolved_request)
    except Exception as error:
        return _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} failed: {type(error).__name__}",
        )

    if not isinstance(imported, AdvisoryImport):
        return _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} returned an unsupported result type",
        )
    if imported.source != identity.source or imported.source_format != identity.source_format:
        return _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} returned inconsistent source identity",
            scope_status=imported.scope_status,
            scope_message=imported.scope_message,
        )
    if imported.status not in {"COMPLETED", "ERROR"}:
        return _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} returned unsupported status {imported.status!r}",
            scope_status=imported.scope_status,
            scope_message=imported.scope_message,
        )
    if imported.status == "ERROR" and imported.findings:
        return _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} returned findings with ERROR status",
            scope_status=imported.scope_status,
            scope_message=imported.scope_message,
        )
    if any(finding.source != identity.source for finding in imported.findings):
        return _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} returned inconsistent finding source identity",
            scope_status=imported.scope_status,
            scope_message=imported.scope_message,
        )

    findings = tuple(
        replace(
            finding,
            authority=ADVISORY_AUTHORITY,
            gate_effect=ADVISORY_GATE_EFFECT,
        )
        for finding in imported.findings
    )
    summary = context_summary(context)
    scope_message = f"{imported.scope_message}; {summary}" if imported.scope_message else summary
    return replace(
        imported,
        input_name=identity.input_name,
        source=identity.source,
        source_format=identity.source_format,
        findings=findings,
        scope_message=scope_message,
    )


def _validate_identity(identity: AdvisoryProviderIdentity) -> str | None:
    for field_name in ("provider_id", "input_name", "source", "source_format"):
        value = getattr(identity, field_name)
        if not isinstance(value, str) or not value.strip():
            return f"Advisory provider identity field {field_name!r} must be non-empty text"
    return None


def _validate_request(request: AdvisoryProviderRequest) -> str | None:
    if request.max_file_bytes <= 0:
        return "Advisory provider max_file_bytes must be greater than zero"
    if request.max_context_bytes <= 0:
        return "Advisory provider max_context_bytes must be greater than zero"
    if bool(request.from_ref) != bool(request.to_ref):
        return "Advisory provider --from and --to must be supplied together"
    if request.commit and (request.from_ref or request.to_ref):
        return "Advisory provider commit mode cannot be combined with --from/--to"
    return None


def _validate_context_binding(request: AdvisoryProviderRequest, context: AdvisoryContext) -> None:
    manifest = context.manifest
    if context.repository.resolve() != request.repository.resolve():
        raise ValueError("Advisory context repository does not match provider request")
    if manifest.max_file_bytes != request.max_file_bytes:
        raise ValueError("Advisory context max_file_bytes does not match provider request")
    if manifest.max_context_bytes != request.max_context_bytes:
        raise ValueError("Advisory context max_context_bytes does not match provider request")
    if manifest.from_ref != request.from_ref or manifest.to_ref != request.to_ref:
        raise ValueError("Advisory context branch range does not match provider request")
    if manifest.commit != request.commit:
        raise ValueError("Advisory context commit does not match provider request")


def _provider_error(
    identity: AdvisoryProviderIdentity,
    message: str,
    *,
    scope_status: str = "NOT_CHECKED",
    scope_message: str | None = None,
) -> AdvisoryImport:
    return advisory_error_import(
        input_name=identity.input_name,
        source=identity.source,
        source_format=identity.source_format,
        message=message,
        scope_status=scope_status,
        scope_message=scope_message,
    )
