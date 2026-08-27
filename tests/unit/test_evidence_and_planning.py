from before_deploy.evidence import collect_repository_evidence, collect_requirements_evidence
from before_deploy.inventory import collect_inventory
from before_deploy.planning import build_security_analysis_plan
from before_deploy.project_profile import detect_project_profile


def test_requirements_evidence_uses_only_bounded_documents_and_omits_source_text(tmp_path):
    (tmp_path / "README.md").write_text(
        "Users authenticate with JWT and can upload file attachments.\n", encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text("stripe\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("Payment processing details\n", encoding="utf-8")

    evidence = collect_requirements_evidence(collect_inventory(tmp_path))

    assert {item.signal_id for item in evidence} == {
        "REQUIREMENT-AUTHENTICATION",
        "REQUIREMENT-FILE-UPLOAD",
    }
    assert all("JWT" not in item.title for item in evidence)
    assert all("JWT" not in item.metadata.values() for item in evidence)


def test_planner_selects_only_provided_compatible_capabilities(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"next": "15.0.0"}}\n', encoding="utf-8")
    (tmp_path / "app.ts").write_text("export {}\n", encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    profile = detect_project_profile(inventory)
    evidence = (*collect_repository_evidence(inventory, profile), *collect_requirements_evidence(inventory))

    plan = build_security_analysis_plan(profile, evidence, runnable_controls=())

    assert not plan.control_selections
    assert not plan.adapter_selections
    assert not plan.skill_selections
    assert "External adapters are selected only when explicitly configured by policy." in plan.exclusions
