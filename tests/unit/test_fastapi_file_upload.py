from pathlib import Path

import pytest

from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_upload import FastApiUploadFilenameControl
from before_deploy.inventory import collect_inventory


def _run(tmp_path: Path, source: str):
    (tmp_path / "uploads.py").write_text(source, encoding="utf-8")
    inventory = collect_inventory(tmp_path)
    return FastApiUploadFilenameControl().run(
        ControlContext(repository_root=tmp_path, inventory=inventory)
    )


def test_direct_upload_filename_open_is_a_finding(tmp_path: Path):
    result = _run(
        tmp_path,
        "from fastapi import FastAPI, UploadFile\n"
        "app = FastAPI()\n"
        "@app.post('/upload')\n"
        "async def upload_document(upload: UploadFile):\n"
        "    with open(upload.filename, 'wb') as destination:\n"
        "        await upload.read()\n",
    )

    assert result.execution.status.value == "COMPLETED"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-API-UPLOAD-001"
    assert finding.evidence == {"artifact": "python", "issue": "upload_filename_filesystem_sink"}
    assert finding.location.path == "uploads.py"
    assert finding.location.start_line == 5


def test_sanitized_or_indirect_storage_shapes_are_not_inferred(tmp_path: Path):
    result = _run(
        tmp_path,
        "from pathlib import Path\n"
        "from fastapi import FastAPI, UploadFile\n"
        "app = FastAPI()\n"
        "@app.post('/upload')\n"
        "async def upload_document(upload: UploadFile):\n"
        "    safe_name = Path(upload.filename).name\n"
        "    await save_to_storage(safe_name, upload)\n",
    )

    assert result.execution.status.value == "COMPLETED"
    assert result.findings == ()


@pytest.mark.parametrize(
    "source",
    (
        "from fastapi import FastAPI, UploadFile\n"
        "app = FastAPI()\n"
        "route_path = '/upload'\n"
        "@app.post(route_path)\n"
        "async def upload_document(upload: UploadFile):\n"
        "    open(upload.filename, 'wb')\n",
        "from fastapi import FastAPI, UploadFile\n"
        "app = FastAPI()\n"
        "@app.post('/upload')\n"
        "async def upload_document(upload: UploadFile | None):\n"
        "    open(upload.filename, 'wb')\n",
        "class App:\n"
        "    def post(self, path):\n"
        "        return lambda function: function\n"
        "app = App()\n"
        "@app.post('/upload')\n"
        "async def upload_document(upload: UploadFile):\n"
        "    open(upload.filename, 'wb')\n",
    ),
)
def test_dynamic_union_or_non_fastapi_shapes_are_excluded(tmp_path: Path, source: str):
    result = _run(tmp_path, source)

    assert result.execution.status.value == "NOT_APPLICABLE"
    assert result.findings == ()


def test_invalid_python_is_fail_closed(tmp_path: Path):
    (tmp_path / "uploads.py").write_text("from fastapi import UploadFile\n@", encoding="utf-8")
    inventory = collect_inventory(tmp_path)

    with pytest.raises(ValueError, match="Unable to parse Python source"):
        FastApiUploadFilenameControl().run(
            ControlContext(repository_root=tmp_path, inventory=inventory)
        )
