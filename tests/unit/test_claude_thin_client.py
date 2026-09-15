from __future__ import annotations

from json import loads
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "clients" / "claude-code"
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN_MANIFEST = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
SKILL = PLUGIN_ROOT / "skills" / "assure" / "SKILL.md"


def _skill_frontmatter() -> tuple[dict[str, object], str]:
    content = SKILL.read_text(encoding="utf-8")
    assert content.startswith("---\n")
    _, frontmatter, body = content.split("---\n", 2)
    parsed = yaml.safe_load(frontmatter)
    assert isinstance(parsed, dict)
    return parsed, body


def test_claude_marketplace_points_to_thin_client_plugin():
    payload = loads(MARKETPLACE.read_text(encoding="utf-8"))

    assert payload["name"] == "before-deploy-tools"
    assert payload["owner"]["name"] == "Before Deploy contributors"
    assert len(payload["plugins"]) == 1
    plugin = payload["plugins"][0]
    assert plugin["name"] == "before-deploy"
    assert plugin["source"] == "./clients/claude-code"
    assert ".." not in plugin["source"]
    assert (ROOT / plugin["source"]).is_dir()


def test_claude_plugin_manifest_uses_commit_source_identity_during_active_development():
    payload = loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))

    assert payload["name"] == "before-deploy"
    assert payload["displayName"] == "Before Deploy"
    assert payload["license"] == "MIT"
    assert "version" not in payload


def test_assure_skill_is_manual_only_and_grants_no_tool_permissions():
    frontmatter, _ = _skill_frontmatter()

    assert frontmatter["name"] == "assure"
    assert frontmatter["disable-model-invocation"] is True
    assert "allowed-tools" not in frontmatter
    assert frontmatter.get("user-invocable", True) is True


def test_assure_skill_preserves_approval_materialization_and_release_boundaries():
    _, body = _skill_frontmatter()

    required_statements = (
        "Never claim `READY`, `HOLD`, `BLOCK`, or `ERROR` from your own judgment.",
        "Do not infer consent from phrases such as “continue”, “go”, or “fix it”.",
        "Never materialize a patch with `before-deploy regress` unless the user explicitly confirms the exact `patch_sha256`",
        "Never use direct file-editing tools to simulate or bypass Before Deploy patch materialization.",
        "Never fabricate regression execution metadata or stdout/stderr digests.",
        "Only `before-deploy release` can emit the final release status.",
    )
    for statement in required_statements:
        assert statement in body


def test_claude_plugin_has_no_automatic_or_alternate_execution_surface():
    forbidden_components = (
        PLUGIN_ROOT / "hooks",
        PLUGIN_ROOT / "agents",
        PLUGIN_ROOT / "bin",
        PLUGIN_ROOT / ".mcp.json",
        PLUGIN_ROOT / ".lsp.json",
    )

    assert all(not path.exists() for path in forbidden_components)
