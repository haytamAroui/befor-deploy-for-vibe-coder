from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.python_data_integrity import PythonDataIntegrityControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "data.py").write_text(source, encoding="utf-8")
    return PythonDataIntegrityControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_literal_update_and_delete_without_where_are_findings(tmp_path: Path):
    result = _run(
        tmp_path,
        'def purge(cursor):\n'
        '    cursor.execute("DELETE FROM source_only_table")\n'
        '    cursor.executemany("UPDATE source_only_table SET status = \'archived\'")\n',
    )

    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 2
    assert all(
        finding.evidence == {"artifact": "python", "issue": "destructive_sql_without_where"}
        for finding in result.findings
    )
    assert all("source_only_table" not in finding.message for finding in result.findings)


def test_literal_mutations_with_where_are_safe_for_this_control(tmp_path: Path):
    result = _run(
        tmp_path,
        'def update(cursor, account_id):\n'
        '    cursor.execute("UPDATE account_records SET status = \'archived\' WHERE id = ?", (account_id,))\n'
        '    cursor.execute("DELETE FROM account_records WHERE id = ?", (account_id,))\n',
    )

    assert result.findings == ()


@pytest.mark.parametrize(
    "source",
    (
        'def dynamic(cursor, table):\n    cursor.execute(f"DELETE FROM {table}")\n',
        'def variable(cursor, query):\n    cursor.execute(query)\n',
        'class Repository:\n    def delete_all(self):\n        self.objects.delete()\n',
        'def select(cursor):\n    cursor.execute("SELECT * FROM account_records")\n',
    ),
)
def test_dynamic_variables_orm_and_non_mutation_are_excluded(tmp_path: Path, source: str):
    result = _run(tmp_path, source)

    assert result.findings == ()


def test_invalid_python_is_fail_closed(tmp_path: Path):
    (tmp_path / "data.py").write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unable to parse Python source"):
        PythonDataIntegrityControl().run(
            ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
        )
