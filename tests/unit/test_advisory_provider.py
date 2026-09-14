from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from before_deploy.advisory import AdvisoryFinding, AdvisoryImport
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
        if self.error is not None:
            raise self.error
        assert self.imported is not None
        return self.imported


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
        location=Location(path="src/app.py", start_line=4, end_line=4),
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
    provider = _Provider(imported=_import(_finding(authority="DETERMINISTIC", gate_effect="BLOCK")))

    result = execute_advisory_provider(
        provider,
        AdvisoryProviderRequest(repository=tmp_path),
    )

    assert provider.calls == 1
    assert result.status == "COMPLETED"
    assert result.input_name == "fake-provider"
    assert result.source == "fake-reviewer"
    assert result.source_format == "fake-json-v1"
    assert len(result.findings) == 1
    assert result.findings[0].authority == "ADVISORY"
    assert result.findings[0].gate_effect == "NONE"


def test_provider_exception_becomes_gate_neutral_source_error(tmp_path: Path):
    provider = _Provider(error=RuntimeError("provider exploded"))

    result = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=tmp_path))

    assert provider.calls == 1
    assert result.status == "ERROR"
    assert result.findings == ()
    assert result.source == "fake-reviewer"
    assert "RuntimeError" in (result.message or "")


def test_provider_source_identity_mismatch_is_discarded(tmp_path: Path):
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

    result = execute_advisory_provider(provider, AdvisoryProviderRequest(repository=tmp_path))

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
