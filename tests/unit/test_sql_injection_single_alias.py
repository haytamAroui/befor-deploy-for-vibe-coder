from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.injection import SqlInjectionSingleLocalAliasControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "queries.py").write_text(source, encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    context = ControlContext(repository_root=tmp_path, inventory=inventory)
    return SqlInjectionSingleLocalAliasControl().run(context)


@pytest.mark.parametrize(
    ("construction", "source"),
    (
        (
            "f_string",
            "def find(cursor, user_id):\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    aliased_query = query\n"
            "    cursor.execute(aliased_query)\n",
        ),
        (
            "percent_format",
            "def find(cursor, user_id):\n"
            "    query = \"SELECT * FROM users WHERE id = %s\" % user_id\n"
            "    aliased_query = query\n"
            "    cursor.executemany(aliased_query)\n",
        ),
        (
            "format_method",
            "async def find(cursor, user_id):\n"
            "    query = \"SELECT * FROM users WHERE id = {}\".format(user_id)\n"
            "    aliased_query = query\n"
            "    await cursor.execute(aliased_query)\n",
        ),
    ),
)
def test_single_alias_control_detects_one_local_name_alias(
    tmp_path: Path, construction: str, source: str
):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 1
    assert result.findings[0].evidence == {
        "construction": construction,
        "sink": "executemany" if construction == "percent_format" else "execute",
        "flow": "single_local_name_alias",
    }
    assert "user_id" not in result.findings[0].message
    assert "SELECT" not in result.findings[0].message


@pytest.mark.parametrize(
    "source",
    (
        "def safe_after_reassignment(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    query = \"SELECT * FROM users WHERE id = ?\"\n"
        "    aliased_query = query\n"
        "    cursor.execute(aliased_query, (user_id,))\n",
        "def alias_chain_is_out_of_scope(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    alias_one = query\n"
        "    alias_two = alias_one\n"
        "    cursor.execute(alias_two)\n",
        "def branch_is_out_of_scope(cursor, user_id, enabled):\n"
        "    if enabled:\n"
        "        query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "        aliased_query = query\n"
        "    cursor.execute(aliased_query)\n",
        "def annotated_alias_is_out_of_scope(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    aliased_query: str = query\n"
        "    cursor.execute(aliased_query)\n",
        "def wrapped_sink_is_out_of_scope(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    aliased_query = query\n"
        "    return cursor.execute(aliased_query)\n",
        "def direct_sink_is_reserved_for_the_existing_control(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n",
    ),
)
def test_single_alias_control_does_not_infer_excluded_flow(tmp_path: Path, source: str):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "COMPLETED"
    assert not result.findings


def test_single_alias_control_is_not_applicable_without_python_source(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("not Python", encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    result = SqlInjectionSingleLocalAliasControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )

    assert result.execution.status.value == "NOT_APPLICABLE"
    assert result.execution.applicable is False


def test_single_alias_control_preserves_the_construction_copied_to_the_alias(tmp_path: Path):
    result = _run(
        tmp_path,
        "def source_reassigned_after_alias(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    aliased_query = query\n"
        "    query = \"SELECT * FROM users WHERE id = ?\"\n"
        "    cursor.execute(aliased_query)\n",
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence == {
        "construction": "f_string",
        "sink": "execute",
        "flow": "single_local_name_alias",
    }
