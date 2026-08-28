from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.python_sensitive_data import PythonSensitiveDataLoggingControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "data.py").write_text(source, encoding="utf-8")
    return PythonSensitiveDataLoggingControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_sensitive_values_to_explicit_loggers_are_findings(tmp_path: Path):
    result = _run(
        tmp_path,
        'import logging\n'
        'logger = logging.getLogger(__name__)\n'
        'def record(user):\n'
        '    logger.info("user=%s", user.password)\n'
        '    logging.warning(user.access_token)\n',
    )
    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 2
    assert all(finding.severity.value == "HIGH" for finding in result.findings)
    assert all(finding.evidence["issue"] == "sensitive_value_to_logger" for finding in result.findings)
    assert all("password" not in finding.message for finding in result.findings)
    assert all("access_token" not in finding.message for finding in result.findings)


def test_literal_messages_and_non_sensitive_values_are_safe_for_this_control(tmp_path: Path):
    result = _run(
        tmp_path,
        'import logging\n'
        'logger = logging.getLogger(__name__)\n'
        'def record(user):\n'
        '    logger.info("password supplied")\n'
        '    logger.debug("user id=%s", user.id)\n',
    )
    assert result.findings == ()


@pytest.mark.parametrize(
    "source",
    (
        'def record(user):\n    logger.info("%s", get_password(user))\n',
        'def record(user):\n    custom.info(user.password)\n',
        'def record(user):\n    logger.info("password=%s", value)\n',
        'def record(user):\n    print(user.password)\n',
    ),
)
def test_wrapped_alias_and_non_logging_cases_are_excluded(tmp_path: Path, source: str):
    result = _run(tmp_path, source)
    assert result.findings == ()


def test_invalid_python_is_fail_closed(tmp_path: Path):
    (tmp_path / "data.py").write_text("def broken(:\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unable to parse Python source"):
        PythonSensitiveDataLoggingControl().run(
            ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
        )
