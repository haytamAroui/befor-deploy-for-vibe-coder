from pathlib import Path

from before_deploy.capabilities import load_builtin_capability_registry
from before_deploy.controls.base import ControlContext
from before_deploy.controls.spring_config import SpringActuatorExposureControl
from before_deploy.domains import load_builtin_security_domain_catalog
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus
from before_deploy.project_profile import detect_project_profile, select_compatible_controls


def _run(tmp_path: Path, relative_path: str, content: str):
    path = tmp_path / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return SpringActuatorExposureControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_wildcard_actuator_exposure_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        "src/main/resources/application.properties",
        "management.endpoints.web.exposure.include=*\n",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-SPRING-ACTUATOR-001"
    assert finding.location is not None
    assert finding.location.path == "src/main/resources/application.properties"
    assert finding.location.start_line == 1
    assert finding.evidence == {
        "artifact": "spring_boot_properties",
        "setting": "management.endpoints.web.exposure.include",
        "value": "wildcard",
    }


def test_explicit_actuator_allowlist_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        "src/main/resources/application.properties",
        "management.endpoints.web.exposure.include=health,info\n",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_commented_wildcard_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        "application.properties",
        "# management.endpoints.web.exposure.include=*\n",
    )

    assert result.findings == ()


def test_unsupported_profile_properties_are_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        "src/main/resources/application-dev.properties",
        "management.endpoints.web.exposure.include=*\n",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_yaml_actuator_configuration_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        "src/main/resources/application.yml",
        "management:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_continuation_form_is_not_interpreted(tmp_path: Path):
    result = _run(
        tmp_path,
        "application.properties",
        "management.endpoints.web.exposure.include=\\\n*\n",
    )

    assert result.findings == ()


def test_spring_profile_registry_and_control_contract_resolve(tmp_path: Path):
    (tmp_path / "pom.xml").write_text(
        "<project><dependency>spring-boot</dependency></project>",
        encoding="utf-8",
    )
    (tmp_path / "src/main/resources").mkdir(parents=True)
    (tmp_path / "src/main/resources/application.properties").write_text(
        "management.endpoints.web.exposure.include=health,info\n",
        encoding="utf-8",
    )

    inventory = collect_inventory(tmp_path)
    profile = detect_project_profile(inventory)
    registry = load_builtin_capability_registry()
    domain_catalog = load_builtin_security_domain_catalog()

    assert "Java" in profile.languages
    assert "Spring" in profile.frameworks

    definition = registry.definition_for_implementation("SEC-SPRING-ACTUATOR-001")
    assert definition is not None
    assert definition.frameworks == frozenset({"Spring"})

    contract = domain_catalog.control_for_implementation("SEC-SPRING-ACTUATOR-001")
    assert contract is not None
    assert contract.control_id == "CONTROL-CONFIG-SPRING-ACTUATOR-001"
    assert contract.security_domain_ids == ("DOMAIN-PRODUCTION-CONFIGURATION-001",)

    runnable, not_applicable = select_compatible_controls(
        (SpringActuatorExposureControl(),),
        profile,
        registry=registry,
    )
    assert len(runnable) == 1
    assert not_applicable == ()
