"""Architecture boundary: the deterministic half must not require the advisory plane.

Preflight's product claim is that the deterministic gate decides and the model-refereed advisory
plane cannot. That claim was documented but not enforced: ``before-deploy scan`` and the release
decision imported the advisory/provider stack at module scope, so the deterministic half could not
even be loaded on a machine without it.

What is enforced here:

* the scan engine (``orchestrator``, ``policy``, ``controls``, ``domains``, ``models``) has no
  module-scope advisory import at all;
* the ``scan`` command imports and runs end to end with the advisory plane unavailable and no
  provider credential in the environment.

What is **not** yet enforced, and is deliberately not asserted here so the suite stays honest
rather than aspirational: the human-authority chain (``verification``, ``human_approval_patch``,
``regression_evidence``, and therefore ``release_disposition``) still reaches the advisory plane,
because ``remediation_proposal`` *calls* ``validate_evidence_explanation`` and
``validate_evidence_explanation_request`` at runtime. Severing that needs the explanation contract
moved into a neutral module — a design change, not an import change. When that happens, add those
modules to ``ADVISORY_FREE_MODULES`` and this test will hold the line.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"

#: Modules that must import with no advisory/provider module importable.
ADVISORY_FREE_MODULES: tuple[str, ...] = (
    "before_deploy.orchestrator",
    "before_deploy.policy",
    "before_deploy.controls.injection",
    "before_deploy.domains",
    "before_deploy.cli",
)

#: The scan engine directories whose every module must be advisory-free.
ENGINE_PACKAGES: tuple[str, ...] = (
    "controls",
    "domains",
)
#: The scan engine single-module files whose every module must be advisory-free.
ENGINE_MODULES: tuple[str, ...] = (
    "orchestrator",
    "policy",
    "models",
    "inventory",
    "waivers",
)

#: Modules that talk to a model provider or consume its output. Importing any of these is what
#: "requires the advisory plane" means here.
ADVISORY_PLANE_PREFIXES: tuple[str, ...] = (
    "advisory",
    "evidence_",
    "assurance_",
    "review_benchmark",
    "ocr_provider",
    "ocr_advisory",
)

#: Installed as a meta path finder before any ``before_deploy`` import. ``find_spec`` is the API
#: CPython 3.12 actually honours; a ``find_module`` shim silently does nothing, which is how an
#: earlier version of this file passed for the wrong reason.
BLOCKER_SOURCE = '''
import sys
from importlib.abc import MetaPathFinder


class _AdvisoryPlaneBlocker(MetaPathFinder):
    PREFIXES = {prefixes!r}

    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("before_deploy."):
            tail = fullname[len("before_deploy."):]
            if any(tail.startswith(prefix) for prefix in self.PREFIXES):
                raise ImportError("advisory plane is unavailable: " + fullname)
        return None


sys.meta_path.insert(0, _AdvisoryPlaneBlocker())
'''

#: Runs first in the child interpreter: installs the blocker, then proves the blocker works.
PRELUDE = '''
import importlib

import _advisory_plane_blocker

for _name in (
    "before_deploy.advisory",
    "before_deploy.evidence_investigation",
    "before_deploy.review_benchmark",
):
    try:
        importlib.import_module(_name)
    except ImportError:
        continue
    raise SystemExit("advisory plane blocker is ineffective for " + _name)
'''


def _sandbox_environment(tmp_path: Path) -> dict[str, str]:
    """Environment for the child interpreter: no provider credential, source tree on the path."""
    environment = dict(os.environ)
    for name in list(environment):
        if name.startswith("OPENAI") or "ADVISORY" in name.upper():
            environment.pop(name, None)
    environment["PYTHONPATH"] = os.pathsep.join((str(SOURCE_ROOT), str(tmp_path)))
    return environment


def _run_with_advisory_plane_blocked(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    """Run ``body`` in a fresh interpreter in which the advisory plane cannot be imported."""
    (tmp_path / "_advisory_plane_blocker.py").write_text(
        BLOCKER_SOURCE.format(prefixes=ADVISORY_PLANE_PREFIXES), encoding="utf-8"
    )
    return subprocess.run(
        [sys.executable, "-c", PRELUDE + body],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=_sandbox_environment(tmp_path),
        timeout=300,
    )


def _module_scope_advisory_imports(path: Path, relative: Path) -> list[str]:
    """Return module-scope advisory imports, ignoring imports nested in functions or classes."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.ImportFrom) and not child.level and child.module:
                candidates = [child.module]
            elif isinstance(child, ast.Import):
                candidates = [alias.name for alias in child.names]
            else:
                walk(child)
                continue
            for candidate in candidates:
                if not candidate.startswith("before_deploy"):
                    continue
                tail = candidate[len("before_deploy."):]
                if any(tail.startswith(prefix) for prefix in ADVISORY_PLANE_PREFIXES):
                    found.append(f"{relative}:{child.lineno} imports {candidate}")

    walk(tree)
    return found


def test_scan_engine_has_no_module_scope_advisory_import():
    """A module-scope import means the engine cannot load without the model stack at all."""
    offenders: list[str] = []
    for path in sorted(SOURCE_ROOT.glob("before_deploy/**/*.py")):
        relative = path.relative_to(SOURCE_ROOT / "before_deploy")
        head = relative.parts[0]
        if head.endswith(".py"):
            if relative.name[: -len(".py")] not in ENGINE_MODULES:
                continue
        elif head not in ENGINE_PACKAGES:
            continue
        offenders.extend(_module_scope_advisory_imports(path, relative))
    assert offenders == [], (
        "the deterministic engine must not import the advisory plane at module scope:\n  "
        + "\n  ".join(offenders)
    )


def test_advisory_free_modules_import_without_the_advisory_plane(tmp_path):
    imports = "\n".join(
        f"importlib.import_module({name!r})" for name in ADVISORY_FREE_MODULES
    )
    result = _run_with_advisory_plane_blocked(
        tmp_path, f"import importlib\n{imports}\nprint('ok')\n"
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "ok" in result.stdout


def test_scan_command_runs_end_to_end_without_the_advisory_plane(tmp_path):
    """The strongest form of the claim: a real scan, with no model stack importable."""
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    output_dir = tmp_path / "reports"
    body = (
        "from before_deploy.cli import main\n"
        f"raise SystemExit(main(['scan', {str(target)!r}, "
        f"'--output-dir', {str(output_dir)!r}]))\n"
    )
    result = _run_with_advisory_plane_blocked(tmp_path, body)
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert (output_dir / "report.json").is_file()
    assert (output_dir / "report.md").is_file()
    assert (output_dir / "report.sarif").is_file()


def test_blocker_and_sandbox_are_effective(tmp_path):
    """Guards the guard: if the blocker were inert, the tests above would prove nothing.

    Also asserts the sandbox really withholds provider credentials, so a scan passing here cannot
    be explained by an accidentally inherited API key.
    """
    body = (
        "import os\n"
        "assert not os.environ.get('OPENAI_API_KEY'), 'provider credential leaked into sandbox'\n"
        "print('sandbox has no provider credential')\n"
    )
    result = _run_with_advisory_plane_blocked(tmp_path, body)
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "no provider credential" in result.stdout
