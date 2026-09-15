from __future__ import annotations

from hashlib import sha256

from before_deploy.advisory import load_advisory_file


def test_advisory_file_retains_raw_digest_without_raw_content(tmp_path):
    raw = b'[{"path":"src/app.py","content":"possible bug","severity":"high"}]'
    path = tmp_path / "provider.json"
    path.write_bytes(raw)

    imported = load_advisory_file(path)

    assert imported.raw_artifact is not None
    assert imported.raw_artifact.sha256 == sha256(raw).hexdigest()
    assert imported.raw_artifact.size_bytes == len(raw)
    assert imported.raw_artifact.media_type == "application/json"
    assert imported.raw_artifact.schema == "ocr-json"
    assert imported.execution is None
    assert not hasattr(imported.raw_artifact, "content")
