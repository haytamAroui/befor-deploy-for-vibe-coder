"""Provenance evidence for the vendored real-world validation snapshots.

Each test is the `evidence_test` cited by one label in
`fixtures/real-world-validation/*/manifest.json`. The tests execute nothing from the vendored
snapshots: the snapshots are third-party files whose upstream dependencies are not installed here,
so each test pins the labeled root cause to the vendored bytes and confirms that the paired fixed
revision changed exactly that construct.

These are drift checks, not trust primitives. They exist so that a snapshot that silently changes,
or a label that no longer matches its snapshot, fails the deterministic suite instead of quietly
scoring a real-world benchmark run.
"""

from __future__ import annotations

from json import loads
from pathlib import Path

FIXTURE_ROOT = Path("fixtures/real-world-validation")


def _lines(bucket: str, role: str, name: str) -> list[str]:
    path = FIXTURE_ROOT / bucket / role / "pkg" / name
    return path.read_text(encoding="utf-8").splitlines()


def _labeled_lines(bucket: str, defect_id: str) -> list[str]:
    """Return the vendored lines covered by one corpus label, from the label's own anchor."""
    corpus = loads((FIXTURE_ROOT / bucket / "corpus.json").read_text(encoding="utf-8"))
    manifest = loads((FIXTURE_ROOT / bucket / "manifest.json").read_text(encoding="utf-8"))
    defect = next(item for item in corpus["benchmark"]["defects"] if item["id"] == defect_id)
    label = next(item for item in manifest["labels"] if item["id"] == defect_id)
    assert label["path"] == defect["path"]
    assert (label["start_line"], label["end_line"]) == (
        defect["start_line"],
        defect["end_line"],
    )
    assert label["category"] == defect["category"]
    relative = Path(defect["path"]).relative_to(FIXTURE_ROOT)
    source = (FIXTURE_ROOT / relative).read_text(encoding="utf-8").splitlines()
    return source[defect["start_line"] - 1 : defect["end_line"]]


def _index_of(lines: list[str], needle: str) -> int:
    matches = [number for number, line in enumerate(lines) if needle in line]
    assert len(matches) == 1, f"expected exactly one {needle!r} line, found {len(matches)}"
    return matches[0]


def test_snapshot_rw_3f7a_web_urldispatcher_containment_check_guarded_by_symlink_flag():
    labeled = "\n".join(_labeled_lines("rw-3f7a", "D-0101"))
    assert "if not self._follow_symlinks:" in labeled
    assert "filepath.relative_to(self._directory)" in labeled

    vulnerable = _lines("rw-3f7a", "vulnerable", "web_urldispatcher.py")
    # Pre-fix: the containment check is unreachable when symlinks are followed.
    assert "                filepath.relative_to(self._directory)" in vulnerable

    secure = _lines("rw-3f7a", "secure", "web_urldispatcher.py")
    assert "                    normalized_path.relative_to(self._directory)" in secure
    assert secure != vulnerable


def test_snapshot_rw_3f7a_http_parser_header_name_checked_before_indexing():
    labeled = "\n".join(_labeled_lines("rw-3f7a", "D-0102"))
    assert "bname[0]" in labeled
    assert "bname[-1]" in labeled

    vulnerable = _lines("rw-3f7a", "vulnerable", "http_parser.py")
    # Pre-fix: the whitespace index check runs with no preceding emptiness rejection.
    index = next(
        number
        for number, line in enumerate(vulnerable)
        if "{bname[0], bname[-1]}" in line
    )
    assert not any(
        "len(bname) == 0" in line for line in vulnerable[index - 3 : index + 1]
    )

    secure = _lines("rw-3f7a", "secure", "http_parser.py")
    assert any("len(bname) == 0" in line for line in secure)


def test_snapshot_rw_9k2m_safe_join_absolute_path_bypass():
    labeled = "\n".join(_labeled_lines("rw-9k2m", "D-0201"))
    assert "os.path.isabs(filename)" in labeled

    vulnerable = _lines("rw-9k2m", "vulnerable", "security.py")
    # Pre-fix: a leading forward slash is not rejected by os.path.isabs alone.
    assert not any('filename.startswith("/")' in line for line in vulnerable)

    secure = _lines("rw-9k2m", "secure", "security.py")
    assert any('filename.startswith("/")' in line for line in secure)


def test_snapshot_rw_9k2m_multipart_field_size_limit_not_accumulated():
    labeled = "\n".join(_labeled_lines("rw-9k2m", "D-0202"))
    assert "elif isinstance(event, Data):" in labeled
    assert "_write(event.data)" in labeled

    vulnerable = _lines("rw-9k2m", "vulnerable", "formparser.py")
    # Pre-fix: no accumulated per-field accounting exists at all.
    assert not any("field_size" in line for line in vulnerable)

    secure = _lines("rw-9k2m", "secure", "formparser.py")
    assert any("field_size += len(event.data)" in line for line in secure)
    assert any("if field_size > self.max_form_memory_size:" in line for line in secure)


def test_snapshot_rw_5p8q_storage_save_name_validated_after_selection_only():
    labeled = "\n".join(_labeled_lines("rw-5p8q", "D-0301"))
    assert "self.get_available_name(name, max_length=max_length)" in labeled

    selection_call = "name = self.get_available_name(name, max_length=max_length)"
    validation_call = "validate_file_name(name, allow_relative_path=True)"
    save_call = "name = self._save(name, content)"

    vulnerable = _lines("rw-5p8q", "vulnerable", "base.py")
    vulnerable_selection = _index_of(vulnerable, selection_call)
    vulnerable_save = _index_of(vulnerable, save_call)
    # Pre-fix: the only validation runs after the file has already been written.
    vulnerable_validations = [
        number for number, line in enumerate(vulnerable) if validation_call in line
    ]
    assert vulnerable_validations == [
        number for number in vulnerable_validations if number > vulnerable_save
    ]
    assert not any(number < vulnerable_selection for number in vulnerable_validations)

    secure = _lines("rw-5p8q", "secure", "base.py")
    secure_selection = _index_of(secure, selection_call)
    secure_validations = [
        number for number, line in enumerate(secure) if validation_call in line
    ]
    assert any(number < secure_selection for number in secure_validations), (
        "fixed revision must validate the name before selection"
    )
    assert any(number > secure_selection for number in secure_validations), (
        "fixed revision must validate the name after selection"
    )


def test_snapshot_rw_5p8q_urlizer_rescans_word_counts_per_part():
    labeled = "\n".join(_labeled_lines("rw-5p8q", "D-0302"))
    assert "middle.endswith(closing)" in labeled
    assert "middle.count(closing)" in labeled

    vulnerable = _lines("rw-5p8q", "vulnerable", "html.py")
    # Pre-fix: counts are recomputed for every word on every scan, with no memoization.
    assert not any("class CountsDict" in line for line in vulnerable)

    secure = _lines("rw-5p8q", "secure", "html.py")
    assert any("class CountsDict" in line for line in secure)
    assert any("def __missing__(self, key):" in line for line in secure)


def test_every_vendored_label_cites_an_existing_evidence_test():
    for bucket in ("rw-3f7a", "rw-9k2m", "rw-5p8q"):
        manifest = loads((FIXTURE_ROOT / bucket / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["labels"], bucket
        for label in manifest["labels"]:
            path_text, _, selector = label["evidence_test"].partition("::")
            source = Path(path_text).read_text(encoding="utf-8")
            assert f"def {selector}(" in source, label["evidence_test"]
