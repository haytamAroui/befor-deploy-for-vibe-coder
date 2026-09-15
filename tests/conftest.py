"""Shared test fixtures for the Before Deploy test suite."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def symlink_supported(tmp_path: Path) -> None:
    """Skip the test where the platform cannot create real symbolic links.

    Symlink handling is a security property worth asserting, but creating a symlink
    requires ``SeCreateSymbolicLinkPrivilege`` on Windows (Developer Mode or an
    elevated shell). Where that privilege is absent, ``os.symlink`` raises
    ``WinError 1314`` and the assertion would report a platform limitation as a
    product failure. The check is a capability probe rather than an OS check, so the
    test still runs wherever symlinks are actually available, including CI.
    """
    probe = tmp_path / "symlink-capability-probe"
    try:
        probe.symlink_to(tmp_path)
    except (OSError, NotImplementedError) as error:  # pragma: no cover - platform dependent
        pytest.skip(f"symbolic links are unavailable on this platform: {error}")
    probe.unlink()
