from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from subprocess import run

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport
from before_deploy.advisory_context import build_advisory_context
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

    @property
    def identity(self) -> AdvisoryProviderIdentity:
        return AdvisoryProviderIdentity(
            provider_id="fake",
            input_name="fake-provider",
            source="fake-reviewer",
            source_format="fake-json-v1",
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


def _import(*findings: AdvisoryFinding) -> AdvisoryImport:
    return AdvisoryImport(
        input_name="provider-native-name",
        source="fake-reviewer",
        source_format="fake-json-v1",
        findings=tuple(findings),
    )


def test_provider_runtime_forces_advisory_authority_and_gate_effect(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(imported=_import(_finding(authority="DETERMINISTIC", gate_effect="BLOCK")))

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


def test_provider_exception_becomes_gate_neutral_source_error(tmp_path: Path):
    repository = _repository(tmp_path)
    provider = _Provider(error=RuntimeError("provider exploded"))

    result = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=repository))

    assert provider.calls == 1
    assert result.status == "ERROR"
    assert result.findings == ()
    assert result.source == "fake-reviewer"
    assert "RuntimeError" in (result.message or "")


def test_provider_source_identity_mismatch_is_discarded(tmp_path: Path):
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
    assert "--from and --to" in (result.message or "")


def test_non_positive_file_limit_is_rejected_before_provider_runs(tmp_path: Path):
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(repository=tmp_path, max_file_bytes=0),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
    assert "max_file_bytes" in (result.message or "")


def test_non_positive_context_limit_is_rejected_before_provider_runs(tmp_path: Path):
    provider = _Provider(imported=_import())

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(repository=tmp_path, max_context_bytes=0),
    )

    assert provider.calls == 0
    assert result.status == "ERROR"
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
    assert "context preparation failed" in (result.message or "").lower()
