import json
from pathlib import Path

import pytest

from before_deploy.agent_repository import RepositoryIndex
from before_deploy.agent_runtime import AgentToolRequest
from before_deploy.agent_tool_executor import BoundedRepositoryTools
from before_deploy.agent_tools import RepositoryToolPolicy


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "app" / "api.py").write_text(
        "from app.policy import authorize\n\n"
        "def endpoint(user):\n"
        "    return authorize(user)\n",
        encoding="utf-8",
    )
    (root / "app" / "policy.py").write_text(
        "def authorize(user):\n"
        "    return user.role == 'admin'\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_policy.py").write_text(
        "from app.policy import authorize\n\n"
        "def test_authorize_denies_member():\n"
        "    assert not authorize(type('U', (), {'role': 'member'})())\n",
        encoding="utf-8",
    )
    return root


def _execute(tools: BoundedRepositoryTools, name: str, arguments: dict, *, max_bytes=64_000):
    result = tools.execute(
        AgentToolRequest(call_id=f"call-{name}", tool_name=name, arguments=arguments),
        max_bytes=max_bytes,
    )
    return result, json.loads(result.content)


def test_repository_index_finds_symbols_references_tests_and_dependencies(tmp_path):
    root = _repo(tmp_path)
    index = RepositoryIndex.build(root)

    assert index.definitions("authorize") == (
        ("app/policy.py", 1, "def authorize(user):"),
    )
    references = index.references("authorize")
    assert any(path == "app/api.py" and line == 1 for path, line, _ in references)
    assert any(path == "tests/test_policy.py" for path, _, _ in references)
    assert any(path == "tests/test_policy.py" for path, _, _ in index.references("authorize", tests_only=True))
    imports, importers = index.dependency_neighbors("app/policy.py")
    assert imports == ()
    assert "app/api.py" in importers
    assert "tests/test_policy.py" in importers


def test_repository_tools_support_dynamic_bounded_exploration(tmp_path):
    tools = BoundedRepositoryTools(_repo(tmp_path), starting_paths=("app/api.py",))

    symbol_result, symbol = _execute(tools, "search_symbol", {"symbol": "authorize"})
    callers_result, callers = _execute(tools, "find_callers", {"symbol": "authorize"})
    tests_result, tests = _execute(tools, "find_tests", {"symbol": "authorize"})
    read_result, read = _execute(
        tools,
        "read_file",
        {"path": "app/policy.py", "start_line": 1, "end_line": 2},
    )

    assert symbol_result.status == "OK"
    assert symbol["definitions"][0]["path"] == "app/policy.py"
    assert any(item["path"] == "app/api.py" for item in callers["call_sites"])
    assert any(item["path"] == "tests/test_policy.py" for item in tests["test_references"])
    assert read["path"] == "app/policy.py"
    assert read_result.evidence_id.startswith("agent-tool:")


def test_scope_expansion_can_be_disabled(tmp_path):
    policy = RepositoryToolPolicy(allow_scope_expansion=False)
    tools = BoundedRepositoryTools(
        _repo(tmp_path),
        starting_paths=("app/api.py",),
        policy=policy,
    )

    result, payload = _execute(tools, "read_file", {"path": "app/policy.py"})

    assert result.status == "DENIED"
    assert payload["error"] == "path_outside_authorized_agent_scope"


def test_path_traversal_and_unknown_tools_are_denied(tmp_path):
    tools = BoundedRepositoryTools(_repo(tmp_path), starting_paths=("app/api.py",))

    traversal, traversal_payload = _execute(tools, "read_file", {"path": "../secret.txt"})
    unknown, unknown_payload = _execute(tools, "shell", {"command": "ignored"})

    assert traversal.status == "DENIED"
    assert traversal_payload["error"] == "path_must_be_repository_relative"
    assert unknown.status == "DENIED"
    assert unknown_payload["error"] == "tool_not_allowed"


def test_symlinked_files_are_not_indexed(tmp_path):
    root = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 'not repository evidence'\n", encoding="utf-8")
    link = root / "app" / "linked.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")

    index = RepositoryIndex.build(root)

    assert "app/linked.py" not in index.files


def test_tool_results_are_replaced_by_hash_metadata_when_byte_bound_is_exceeded(tmp_path):
    root = _repo(tmp_path)
    (root / "app" / "large.py").write_text("needle = 1\n" * 200, encoding="utf-8")
    tools = BoundedRepositoryTools(root)

    result, payload = _execute(tools, "search_text", {"query": "needle"}, max_bytes=200)

    assert result.status == "OK"
    assert result.truncated is True
    assert payload["truncated"] is True
    assert payload["original_size_bytes"] > 200
    assert len(payload["original_sha256"]) == 64
