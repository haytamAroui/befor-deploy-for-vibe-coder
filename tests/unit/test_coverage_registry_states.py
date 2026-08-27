from pathlib import Path

from before_deploy.controls.secrets import SecretDetectionControl
from before_deploy.models import ControlExecution, ExecutionStatus, utc_now
from before_deploy.orchestrator import ScanOrchestrator
from before_deploy.reports import render_json, render_markdown, render_sarif


def test_compatible_registered_capability_absent_from_policy_is_not_selected(tmp_path):
    repository = tmp_path / "next-service"
    repository.mkdir()
    (repository / "package.json").write_text('{"dependencies": {"next": "15.0.0"}}\n', encoding="utf-8")
    (repository / "route.ts").write_text("export {}\n", encoding="utf-8")
    (repository / "openapi.yaml").write_text("openapi: 3.0.0\n", encoding="utf-8")
    policy = _policy(tmp_path / "secret-only.yaml", required=False, allow_errors=True)

    result = ScanOrchestrator((SecretDetectionControl(),)).scan(repository, policy)
    coverage = {item.domain: item.status.value for item in result.coverage_audit.assessments}

    assert result.decision.outcome.value == "PASS"
    assert coverage["Framework: Next.js"] == "NOT_SELECTED"
    assert coverage["Language: TypeScript"] == "NOT_SELECTED"
    assert coverage["API security"] == "NOT_APPLICABLE"


def test_selected_capability_execution_error_is_visible_in_coverage_but_does_not_create_policy_authority(
    tmp_path,
):
    repository = tmp_path / "repository"
    repository.mkdir()
    policy = _policy(tmp_path / "nonrequired.yaml", required=False, allow_errors=True)

    result = ScanOrchestrator((_ErrorSecretControl(),)).scan(repository, policy)
    coverage = {
        (item.domain_id, item.domain): item.status.value for item in result.coverage_audit.assessments
    }

    assert result.decision.outcome.value == "PASS"
    assert coverage[("DOMAIN-SECRETS-001", "Secrets and sensitive configuration")] == "ERROR"


def test_authorization_requirement_signal_is_diagnostic_and_cannot_change_the_gate(tmp_path):
    repository = tmp_path / "authorization-requirements"
    repository.mkdir()
    (repository / "README.md").write_text(
        "The system requires role-based access control for sensitive-authority-token owners.\n",
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "secret-only.yaml", required=False, allow_errors=True)

    result = ScanOrchestrator((SecretDetectionControl(),)).scan(repository, policy)

    coverage = {item.domain: item.status.value for item in result.coverage_audit.assessments}
    assert result.decision.outcome.value == "PASS"
    assert result.findings == ()
    assert coverage["Declared requirement: Authorization"] == "DECLARED_REVIEW_REQUIRED"
    for report in (render_json(result), render_markdown(result), render_sarif(result)):
        assert "Declared requirement: Authorization" in report
        assert "sensitive-authority-token" not in report


def test_domain_coverage_is_partial_when_a_compatible_mapped_contract_is_not_selected(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    policy = _secrets_policy(tmp_path / "native-only.yaml", "SEC-SECRET-001")

    result = ScanOrchestrator((SecretDetectionControl(),)).scan(repository, policy)

    coverage = {
        item.domain_id: item
        for item in result.coverage_audit.assessments
        if item.domain_id == "DOMAIN-SECRETS-001"
    }
    assessment = coverage["DOMAIN-SECRETS-001"]
    assert result.decision.outcome.value == "PASS"
    assert result.findings == ()
    assert assessment.status.value == "PARTIAL"
    assert assessment.rationale == (
        "At least one compatible mapped capability was absent from the active policy selection."
    )


def test_domain_coverage_is_complete_when_all_compatible_mapped_contracts_complete(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    policy = _secrets_policy(
        tmp_path / "native-and-gitleaks.yaml",
        "SEC-SECRET-001",
        "SEC-SECRET-GITLEAKS-001",
    )

    result = ScanOrchestrator((SecretDetectionControl(), _CompletedGitleaksControl())).scan(
        repository, policy
    )

    coverage = {item.domain_id: item.status.value for item in result.coverage_audit.assessments}
    assert result.decision.outcome.value == "PASS"
    assert result.findings == ()
    assert coverage["DOMAIN-SECRETS-001"] == "COVERED"


def _policy(path: Path, *, required: bool, allow_errors: bool) -> Path:
    path.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "profile: coverage-test",
                f"allow_nonrequired_control_errors: {str(allow_errors).lower()}",
                "controls:",
                "  SEC-SECRET-001:",
                f"    required: {str(required).lower()}",
                "    disposition: BLOCK",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def _secrets_policy(path: Path, *control_ids: str) -> Path:
    lines = [
        "schema_version: 1",
        "profile: coverage-contract-test",
        "allow_nonrequired_control_errors: true",
        "controls:",
    ]
    for control_id in control_ids:
        lines.extend(
            [
                f"  {control_id}:",
                "    required: false",
                "    disposition: BLOCK",
            ]
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


class _CompletedGitleaksControl:
    control_id = "SEC-SECRET-GITLEAKS-001"
    control_version = "test"

    def run(self, context):
        now = utc_now()
        return type(
            "ControlResult",
            (),
            {
                "execution": ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.COMPLETED,
                    started_at=now,
                    completed_at=now,
                ),
                "findings": (),
            },
        )()


class _ErrorSecretControl:
    control_id = "SEC-SECRET-001"
    control_version = "test"

    def run(self, context):
        now = utc_now()
        return type(
            "ControlResult",
            (),
            {
                "execution": ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.ERROR,
                    started_at=now,
                    completed_at=now,
                    message="Synthetic failure",
                ),
                "findings": (),
            },
        )()
