from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.spring_cors import SpringCredentialedWildcardCorsControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, source: str):
    path = tmp_path / "src/main/java/example/Controller.java"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return SpringCredentialedWildcardCorsControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_single_line_credentialed_wildcard_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '@CrossOrigin(origins = "*", allowCredentials = "true")\nclass Controller {}\n',
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-SPRING-CORS-001"
    assert finding.location is not None
    assert finding.location.start_line == 1
    assert finding.evidence["origins"] == "wildcard"
    assert finding.evidence["allow_credentials"] == "true"


def test_argument_order_does_not_change_detection(tmp_path: Path):
    result = _run(
        tmp_path,
        '@CrossOrigin(allowCredentials="true", origins="*")\nclass Controller {}\n',
    )

    assert len(result.findings) == 1


def test_explicit_origin_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '@CrossOrigin(origins = "https://app.example", allowCredentials = "true")\nclass Controller {}\n',
    )

    assert result.findings == ()


def test_credentials_false_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '@CrossOrigin(origins = "*", allowCredentials = "false")\nclass Controller {}\n',
    )

    assert result.findings == ()


def test_commented_annotation_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '// @CrossOrigin(origins = "*", allowCredentials = "true")\nclass Controller {}\n',
    )

    assert result.findings == ()


def test_block_commented_annotation_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '/*\n@CrossOrigin(origins = "*", allowCredentials = "true")\n*/\nclass Controller {}\n',
    )

    assert result.findings == ()


def test_multiline_annotation_is_explicitly_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '@CrossOrigin(\n    origins = "*",\n    allowCredentials = "true"\n)\nclass Controller {}\n',
    )

    assert result.findings == ()


def test_constant_origin_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '@CrossOrigin(origins = ALLOWED_ORIGIN, allowCredentials = "true")\nclass Controller {}\n',
    )

    assert result.findings == ()


def test_no_java_source_is_not_applicable(tmp_path: Path):
    (tmp_path / "README.md").write_text("no Java", encoding="utf-8")
    result = SpringCredentialedWildcardCorsControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
