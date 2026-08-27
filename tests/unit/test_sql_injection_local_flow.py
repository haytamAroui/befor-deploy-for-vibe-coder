from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.injection import SqlInjectionControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "queries.py").write_text(source, encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    context = ControlContext(repository_root=tmp_path, inventory=inventory)
    return SqlInjectionControl().run(context)


@pytest.mark.parametrize(
    ("construction", "source"),
    (
        (
            "f_string",
            "def find(cursor, user_id):\n"
            "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "    cursor.execute(query)\n",
        ),
        (
            "percent_format",
            "def find(cursor, user_id):\n"
            "    query = \"SELECT * FROM users WHERE id = %s\" % user_id\n"
            "    cursor.execute(query)\n",
        ),
        (
            "format_method",
            "def find(cursor, user_id):\n"
            "    query = \"SELECT * FROM users WHERE id = {}\".format(user_id)\n"
            "    cursor.execute(query)\n",
        ),
    ),
)
def test_sql_control_detects_straight_line_local_assignment_flow(
    tmp_path: Path, construction: str, source: str
):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 1
    assert result.findings[0].evidence == {
        "construction": construction,
        "sink": "execute",
        "flow": "local_straight_line_assignment",
    }
    assert "user_id" not in result.findings[0].message


@pytest.mark.parametrize(
    "source",
    (
        "def safe_after_reassignment(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    query = \"SELECT * FROM users WHERE id = ?\"\n"
        "    cursor.execute(query, (user_id,))\n",
        "def branch_is_out_of_scope(cursor, user_id, enabled):\n"
        "    if enabled:\n"
        "        query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n",
        "def alias_is_out_of_scope(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    alias = query\n"
        "    cursor.execute(alias)\n",
        "def assigned_sink_is_out_of_scope(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    result = cursor.execute(query)\n"
        "    return result\n",
    ),
)
def test_sql_control_does_not_infer_non_linear_or_non_standalone_flow(tmp_path: Path, source: str):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "COMPLETED"
    assert not result.findings


def test_sql_control_keeps_direct_execute_detection_without_flow_marker(tmp_path: Path):
    result = _run(
        tmp_path,
        "def direct(cursor, user_id):\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence == {"construction": "f_string", "sink": "execute"}
