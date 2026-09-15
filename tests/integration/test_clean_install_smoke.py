"""Clean-install smoke evidence for the release readiness gate.

The release workflow installs the built distribution into an isolated environment and
exports ``PREFLIGHT_CLEAN_INSTALL=1`` before running this module. The scenario verifier
in ``before_deploy.readiness_gate`` treats a skipped run as *not* evidence, so these
tests must actually execute for a release to be considered ready.
"""

import os
import shutil
import subprocess

import pytest

REQUIRED_ENTRY_POINTS = {
    "preflight": "before_deploy.release_entrypoint:main",
    "preflight-mcp": "before_deploy.mcp_server:main",
    "before-deploy": "before_deploy.release_entrypoint:main",
    "before-deploy-mcp": "before_deploy.mcp_server:main",
    "before-deploy-benchmark-compare": "before_deploy.comparative_benchmark_cli:main",
    "before-deploy-caller-pilot": "before_deploy.caller_pilot_runner_cli:main",
    "before-deploy-real-world-validation": "before_deploy.real_world_validation_cli:main",
    "before-deploy-readiness-gate": "before_deploy.readiness_gate:main",
}

pytestmark = pytest.mark.skipif(
    os.environ.get("PREFLIGHT_CLEAN_INSTALL") != "1",
    reason="requires an isolated install of the built distribution",
)


def test_distribution_declares_every_console_entry_point():
    from importlib.metadata import distribution

    entry_points = {
        item.name: item.value
        for item in distribution("before-deploy").entry_points
        if item.group == "console_scripts"
    }
    for name, target in REQUIRED_ENTRY_POINTS.items():
        assert entry_points.get(name) == target, f"missing or relocated entry point {name}"


def test_installed_cli_renders_help_without_importing_from_the_source_tree(tmp_path):
    executable = shutil.which("preflight")
    assert executable, "the installed distribution must expose the preflight executable"

    completed = subprocess.run(
        [executable, "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert "usage" in completed.stdout.lower()
