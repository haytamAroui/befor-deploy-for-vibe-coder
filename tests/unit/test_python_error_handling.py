from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.python_error_handling import PythonErrorHandlingControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return PythonErrorHandlingControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_broad_exception_handlers_with_only_pass_are_findings(tmp_path: Path):
    result = _run(tmp_path, "try:\n    work()\nexcept Exception:\n    pass\n\ntry:\n    work()\nexcept:\n    pass\n")
    assert len(result.findings) == 2
    assert result.findings[0].evidence == {"artifact": "python", "issue": "broad_exception_suppressed"}
    assert "Exception" not in str(result.findings[0].evidence)


def test_handled_or_narrow_exceptions_are_safe_for_this_control(tmp_path: Path):
    result = _run(tmp_path, "try:\n    work()\nexcept OSError:\n    pass\ntry:\n    work()\nexcept Exception:\n    log_error()\n")
    assert result.findings == ()


def test_returns_and_raises_are_ambiguous_and_excluded(tmp_path: Path):
    result = _run(tmp_path, "try:\n    work()\nexcept Exception:\n    return None\n")
    assert result.findings == ()


def test_invalid_python_is_fail_closed(tmp_path: Path):
    (tmp_path / "app.py").write_text("def broken(:\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unable to parse Python source"):
        PythonErrorHandlingControl().run(
            ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
        )
