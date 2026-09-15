from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from subprocess import run

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport
from before_deploy.advisory_context import build_advisory_context
from before_deploy.advisory_execution import (
    MODEL_IDENTITY_ATTESTED,
    AdvisoryExecutionBudget,
    AdvisoryExecutionDescriptor,
    AdvisoryExecutionParameter,
    AdvisoryModelIdentity,
    AdvisoryRawArtifact,
)
from before_deploy.advisory_provider import (
    AdvisoryProviderIdentity,
    AdvisoryProviderRequest,
    execute_advisory_provider,
)
from before_deploy.models import Location


@dataclass
class _Provider:
    imported: AdvisoryImport | None = None
    error: Exception | None = None
    calls: int = 0
    descriptor_error: Exception | None = None

    @property
    def identity(self) -> AdvisoryProviderIdentity:
        return AdvisoryProviderIdentity(
            provider_id="fake",
            input_name="fake-provider",
            source="fake-reviewer",
            source_format="fake-json-v1",
        )

    def execution_descriptor(self, request: AdvisoryProviderRequest) -> AdvisoryExecutionDescriptor:
        assert request.context is not None
        if self.descriptor_error is not None:
            raise self.descriptor_error
        return AdvisoryExecutionDescriptor(
            implementation="fake-reviewer-cli",
            implementation_version="1.2.3",
            model=AdvisoryModelIdentity(
                status=MODEL_IDENTITY_ATTESTED,
                provider="example-ai",
                model="review-model-1",
            ),
            configuration=(
                AdvisoryExecutionParameter(name="mode", value="review"),
                AdvisoryExecutionParameter(name="temperature", value="0"),
            ),
            budgets=(
                AdvisoryExecutionBudget(name="timeout_seconds", limit=30, unit="seconds"),
            ),
        )

    def review(self, request: AdvisoryProviderRequest) -> AdvisoryImport:
        self.calls += 1
        assert request.repository.is_absolute()
        assert request.context is not None
        if self.error is not None:
            raise self.error
        assert self.imported is not None
        return self.imported


def _git(repository: Path, *arguments: str) -> None:
    run(["git", *arguments], cwd=repository, check=True, capture_output=True, text=True)


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Before Deploy Tests")
    _git(repository, "config", "user.email", "tests@before-deploy.invalid")
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "app.py")
    _git(repository, "commit", "-m", "initial")
    (repository / "app.py").write_text("value = 2\n", encoding="utf-8")
    return repository


def _finding(*, authority: str = "ADVISORY", gate_effect: str = "NONE") -> AdvisoryFinding:
    return AdvisoryFinding(
        finding_id="ADV-1",
        source="fake-reviewer",
        title="Possible issue",
        message="Provider claim",
        category="bug",
        severity="high",
        confidence="0.8",
        fingerprint="fake-fingerprint",
        location=Location(path="app.py", start_line=1, end_line=1),
        authority=authority,
        gate_effect=gate_effect,
    )


def _import(*findings: AdvisoryFinding, raw: bool = False) -> AdvisoryImport:
    artifact = None
    if raw:
        raw_bytes = b'{"comments":[]}'
        artifact = AdvisoryRawArtifact(
            sha256=sha256(raw_bytes).hexdigest(),
            size_bytes=len(raw_bytes),
            media_type="application/json",
            schema="fake-json-v1",
        )
    return AdvisoryImport(
        input_name="provider-native-name",
        source="fake-reviewer",
        source_format="fake-json-v1",
        findings=tuple(findings),
        raw_artifact=artifact,
    )


def test_provider_runtime_forces_advisory_authority_and_attests_execution(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(
        imported=_import(_finding(authority="DETERMINISTIC", gate_effect="BLOCK"), raw=True)
    )

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(repository=repository),
    )

    assert provider.calls == 1
    assert result.status == "COMPLETED"
    assert result.input_name == "fake-provider"
    assert result.source == "fake-reviewer"
    assert result.source_format == "fake-json-v1"
    assert len(result.findings) == 1
    assert result.findings[0].authority == "ADVISORY"
    assert result.findings[0].gate_effect == "NONE"
    assert "context_sha256=" in (result.scope_message or "")
    assert "selected_files=1" in (result.scope_message or "")

    execution = result.execution
    assert execution is not None
    assert execution.schema_version == 1
    assert execution.provider_id == "fake"
    assert execution.implementation == "fake-reviewer-cli"
    assert execution.implementation_version == "1.2.3"
    assert execution.model.status == "ATTESTED"
    assert execution.model.provider == "example-ai"
    assert execution.model.model == "review-model-1"
    assert execution.context_sha256 in (result.scope_message or "")
    assert execution.context_selected_files == 1
    assert execution.context_selected_bytes == len(b"value = 2\n")
    assert execution.duration_ms >= 0
    assert execution.completed_at >= execution.started_at
    assert len(execution.configuration_sha256) == 64
    assert len(execution.normalized_output_sha256) == 64
    assert execution.result_status == "COMPLETED"
    assert execution.authority == "ADVISORY_EXECUTION"
    assert execution.gate_effect == "NONE"
    assert execution.raw_output == result.raw_artifact


def test_provider_configuration_hash_is_stable_across_repeated_runs(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(imported=_import())

    first = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=repository))
    second = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=repository))

    assert first.execution is not None
    assert second.execution is not None
    assert first.execution.configuration_sha256 == second.execution.configuration_sha256
    assert first.execution.context_sha256 == second.execution.context_sha256
    assert first.execution.normalized_output_sha256 == second.execution.normalized_output_sha256
    assert first.execution.started_at != second.execution.started_at


def test_provider_exception_becomes_attested_gate_neutral_source_error(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(error=RuntimeError("provider exploded"))

    result = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=repository))

    assert provider.calls == 1
    assert result.status == "ERROR"
    assert result.findings == ()
    assert result.source == "fake-reviewer"
    assert "RuntimeError" in (result.message or "")
    assert result.execution is not None
    assert result.execution.result_status == "ERROR"
    assert result.execution.raw_output is None
    assert result.execution.gate_effect == "NONE"


def test_provider_source_identity_mismatch_is_discarded_but_execution_is_attested(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(
        imported=AdvisoryImport(
            input_name="spoofed",
            source="deterministic-core",
            source_format="fake-json-v1",
            findings=(_finding(),),
            scope_status="PARTIAL",
            scope_message="provider reviewed a subset",
        )
    )

    result = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=repository))

    assert result.status == "ERROR"
    assert result.findings == ()
    assert result.source == "fake-reviewer"
    assert result.scope_status == "PARTIAL"
    assert result.scope_message == "provider reviewed a subset"
    assert "inconsistent source identity" in (result.message or "")
    assert result.execution is not None
    assert result.execution.result_status == "ERROR"


def test_invalid_execution_descriptor_stops_before_provider_runs(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(
        imported=_import(),
        descriptor_error=ValueError("bad descriptor"),
    )

    result = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=repository))

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert result.execution is None
    assert "execution descriptor" in (result.message or "").lower()


def test_invalid_common_scope_is_rejected_before_provider_runs(tmp_path: Path):
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(
            repository=tmp_path,
            from_ref="main",
            to_ref=None,
        ),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert result.findings == ()
    assert result.execution is None
    assert "--from and --to" in (result.message or "")


def test_non_positive_file_limit_is_rejected_before_provider_runs(tmp_path: Path):
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(repository=tmp_path, max_file_bytes=0),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert result.execution is None
    assert "max_file_bytes" in (result.message or "")


def test_non_positive_context_limit_is_rejected_before_provider_runs(tmp_path: Path):
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(repository=tmp_path, max_context_bytes=0),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert result.execution is None
    assert "max_context_bytes" in (result.message or "")


def test_prebuilt_context_must_match_request_bounds(tmp_path: Path):
    repository = _repository(tmp_path)
    context = build_advisory_context(
        repository,
        max_file_bytes=1000,
        max_context_bytes=2000,
    )
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(
            repository=repository,
            max_file_bytes=1000,
            max_context_bytes=3000,
            context=context,
        ),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert result.execution is None
    assert "context preparation failed" in (result.message or "").lower()


def test_tampered_prebuilt_context_is_rejected_before_provider_runs(tmp_path: Path):
    repository = _repository(tmp_path)
    context = build_advisory_context(
        repository,
        max_file_bytes=1000,
        max_context_bytes=2000,
    )
    tampered = replace(
        context,
        files=(replace(context.files[0], content="different bytes\n"),),
    )
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(
            repository=repository,
            max_file_bytes=1000,
            max_context_bytes=2000,
            context=tampered,
        ),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert result.execution is None
    assert "context preparation failed" in (result.message or "").lower()
