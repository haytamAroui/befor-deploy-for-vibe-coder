from pathlib import Path
import pytest
from before_deploy.controls.base import ControlContext
from before_deploy.controls.python_observability import PythonObservabilityControl
from before_deploy.inventory import collect_inventory

def _run(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return PythonObservabilityControl().run(ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path)))

def test_direct_prints_are_findings_and_redacted(tmp_path: Path):
    result = _run(tmp_path, 'def run(value):\n    print(value)\n    print("done")\n')
    assert len(result.findings) == 2
    assert all(f.evidence == {"artifact": "python", "issue": "direct_print_output"} for f in result.findings)
    assert "value" not in str(result.findings[0].evidence)

def test_structured_logging_is_safe(tmp_path: Path):
    result = _run(tmp_path, 'import logging\nlogger = logging.getLogger(__name__)\nlogger.info("done")\n')
    assert result.findings == ()

def test_print_alias_is_ambiguous_and_excluded(tmp_path: Path):
    result = _run(tmp_path, 'output = print\noutput("value")\n')
    assert result.findings == ()

def test_invalid_python_fails_closed(tmp_path: Path):
    (tmp_path / "app.py").write_text("def broken(:\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unable to parse Python source"):
        PythonObservabilityControl().run(ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path)))
