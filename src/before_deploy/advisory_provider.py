"""Provider runtime for non-authoritative advisory review execution."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from json import dumps
from pathlib import Path
from time import perf_counter_ns
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
from before_deploy.advisory_execution import (
    ADVISORY_EXECUTION_SCHEMA_VERSION,
    AdvisoryExecutionDescriptor,
    AdvisoryExecutionProvenance,
    AdvisoryRawArtifact,
    configuration_sha256,
    normalize_execution_descriptor,
    validate_raw_artifact,
)
from before_deploy.models import to_primitive, utc_now


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

    def execution_descriptor(self, request: AdvisoryProviderRequest) -> AdvisoryExecutionDescriptor: ...

    def review(self, request: AdvisoryProviderRequest) -> AdvisoryImport: ...


def execute_advisory_provider(
    provider: AdvisoryProvider,
    request: AdvisoryProviderRequest,
) -> AdvisoryImport:
    """Execute one provider and attach content-free execution provenance."""
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
        descriptor = normalize_execution_descriptor(provider.execution_descriptor(resolved_request))
    except (AttributeError, TypeError, ValueError) as error:
        return _provider_error(
            identity,
            f"Advisory execution descriptor was invalid: {type(error).__name__}",
        )

    started_at = utc_now()
    started_ns = perf_counter_ns()
    try:
        imported = provider.review(resolved_request)
    except Exception as error:
        completed_at = utc_now()
        completed_ns = perf_counter_ns()
        failed = _provider_error(
            identity,
            f"Advisory provider {identity.provider_id!r} failed: {type(error).__name__}",
        )
        return _attach_execution(
            failed,
            identity=identity,
            descriptor=descriptor,
            context=context,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=_duration_ms(started_ns, completed_ns),
            raw_output=None,
        )

    completed_at = utc_now()
    completed_ns = perf_counter_ns()
    duration_ms = _duration_ms(started_ns, completed_ns)
    raw_output = imported.raw_artifact if isinstance(imported, AdvisoryImport) else None
    if raw_output is not None:
        try:
            validate_raw_artifact(raw_output)
        except ValueError:
            invalid = _provider_error(
                identity,
                f"Advisory provider {identity.provider_id!r} returned invalid raw-output provenance",
            )
            return _attach_execution(
                invalid,
                identity=identity,
                descriptor=descriptor,
                context=context,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                raw_output=None,
            )

    validation_error = _provider_result_error(identity, imported)
    if validation_error is not None:
        invalid = _provider_error(
            identity,
            validation_error,
            scope_status=imported.scope_status if isinstance(imported, AdvisoryImport) else "NOT_CHECKED",
            scope_message=imported.scope_message if isinstance(imported, AdvisoryImport) else None,
        )
        return _attach_execution(
            invalid,
            identity=identity,
            descriptor=descriptor,
            context=context,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            raw_output=raw_output,
        )

    assert isinstance(imported, AdvisoryImport)
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
    normalized = replace(
        imported,
        input_name=identity.input_name,
        source=identity.source,
        source_format=identity.source_format,
        findings=findings,
        scope_message=scope_message,
        execution=None,
    )
    return _attach_execution(
        normalized,
        identity=identity,
        descriptor=descriptor,
        context=context,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        raw_output=raw_output,
    )


def _provider_result_error(identity: AdvisoryProviderIdentity, imported: object) -> str | None:
    if not isinstance(imported, AdvisoryImport):
        return f"Advisory provider {identity.provider_id!r} returned an unsupported result type"
    if imported.source != identity.source or imported.source_format != identity.source_format:
        return f"Advisory provider {identity.provider_id!r} returned inconsistent source identity"
    if imported.status not in {"COMPLETED", "ERROR"}:
        return (
            f"Advisory provider {identity.provider_id!r} returned unsupported status "
            f"{imported.status!r}"
        )
    if imported.status == "ERROR" and imported.findings:
        return f"Advisory provider {identity.provider_id!r} returned findings with ERROR status"
    if any(finding.source != identity.source for finding in imported.findings):
        return f"Advisory provider {identity.provider_id!r} returned inconsistent finding source identity"
    return None


def _attach_execution(
    imported: AdvisoryImport,
    *,
    identity: AdvisoryProviderIdentity,
    descriptor: AdvisoryExecutionDescriptor,
    context: AdvisoryContext,
    started_at,
    completed_at,
    duration_ms: int,
    raw_output: AdvisoryRawArtifact | None,
) -> AdvisoryImport:
    normalized_digest = _normalized_output_sha256(imported)
    provenance = AdvisoryExecutionProvenance(
        schema_version=ADVISORY_EXECUTION_SCHEMA_VERSION,
        provider_id=identity.provider_id,
        implementation=descriptor.implementation,
        implementation_version=descriptor.implementation_version,
        model=descriptor.model,
        configuration=descriptor.configuration,
        configuration_sha256=configuration_sha256(descriptor),
        budgets=descriptor.budgets,
        context_sha256=context.manifest.context_sha256,
        context_selected_files=context.manifest.selected_file_count,
        context_selected_bytes=context.manifest.total_selected_bytes,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        raw_output=raw_output,
        normalized_output_sha256=normalized_digest,
        result_status=imported.status,
    )
    return replace(imported, execution=provenance)


def _normalized_output_sha256(imported: AdvisoryImport) -> str:
    payload = {
        "input_name": imported.input_name,
        "source": imported.source,
        "source_format": imported.source_format,
        "status": imported.status,
        "message": imported.message,
        "scope_status": imported.scope_status,
        "scope_message": imported.scope_message,
        "findings": to_primitive(imported.findings),
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(serialized.encode("utf-8")).hexdigest()


def _duration_ms(started_ns: int, completed_ns: int) -> int:
    return max(0, (completed_ns - started_ns) // 1_000_000)


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
