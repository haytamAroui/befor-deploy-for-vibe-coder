from pathlib import Path

from before_deploy.controls import native_controls
from before_deploy.controls.base import ControlContext
from before_deploy.controls.fastapi_command_injection import FastApiDirectCommandInjectionControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus, Severity
from before_deploy.orchestrator import ScanOrchestrator, configured_controls
from before_deploy.policy import load_policy


REPOSITORY = Path(__file__).parents[2]
POLICY = REPOSITORY / "rules" / "fastapi-command-injection-policy.yaml"


def _run(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return FastApiDirectCommandInjectionControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_route_parameter_to_os_system_is_blocker(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
import os
app = FastAPI()

@app.get("/run")
def run(command: str):
    os.system(command)
    return {"ok": True}
""",
    )
    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-FASTAPI-COMMAND-INJECTION-001"
    assert finding.severity == Severity.BLOCKER
    assert finding.evidence["sink"] == "os.system"
    assert finding.evidence["request_parameter"] == "command"


def test_direct_route_parameter_to_subprocess_shell_true_is_blocker(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
import subprocess
app = FastAPI()

@app.post("/run")
def run(command: str):
    subprocess.run(command, shell=True, check=True)
    return {"ok": True}
""",
    )
    assert len(result.findings) == 1
    assert result.findings[0].evidence["sink"] == "subprocess.run"


def test_direct_imported_popen_is_supported(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
from subprocess import Popen
app = FastAPI()

@app.post("/run")
def run(command: str):
    Popen(command, shell=True)
    return {"ok": True}
""",
    )
    assert len(result.findings) == 1
    assert result.findings[0].evidence["sink"] == "subprocess.Popen"


def test_subprocess_without_shell_true_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
import subprocess
app = FastAPI()

@app.post("/run")
def run(command: str):
    subprocess.run(command)
    return {"ok": True}
""",
    )
    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_constant_shell_command_is_not_request_flow(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
import subprocess
app = FastAPI()

@app.post("/run")
def run(command: str):
    subprocess.run("echo ok", shell=True)
    return {"ok": True}
""",
    )
    assert result.findings == ()


def test_fstring_and_local_alias_are_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
import os
app = FastAPI()

@app.get("/run")
def run(command: str):
    target = command
    os.system(target)
    os.system(f"echo {command}")
    return {"ok": True}
""",
    )
    assert result.findings == ()


def test_depends_string_parameter_is_not_treated_as_request_input(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import Depends, FastAPI
import os
app = FastAPI()

def internal_command():
    return "echo ok"

@app.get("/run")
def run(command: str = Depends(internal_command)):
    os.system(command)
    return {"ok": True}
""",
    )
    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_shadowed_os_name_is_rejected(tmp_path: Path):
    result = _run(
        tmp_path,
        """
from fastapi import FastAPI
import os
app = FastAPI()

@app.get("/run")
def run(command: str, os=None):
    os.system(command)
    return {"ok": True}
""",
    )
    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_focused_policy_blocks_direct_command_injection(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        """
from fastapi import FastAPI
import os
app = FastAPI()

@app.get("/run")
def run(command: str):
    os.system(command)
    return {"ok": True}
""",
        encoding="utf-8",
    )
    profile = load_policy(POLICY)
    controls = configured_controls(profile, native_controls())
    result = ScanOrchestrator(controls).scan(tmp_path, POLICY)

    assert result.decision.outcome.value == "BLOCK"
    assert {finding.rule_id for finding in result.findings} == {"SEC-FASTAPI-COMMAND-INJECTION-001"}
    assert result.security_analysis_plan is not None
    contract = next(
        item
        for item in result.security_analysis_plan.control_contract_selections
        if item.implementation_id == "SEC-FASTAPI-COMMAND-INJECTION-001"
    )
    assert contract.control_id == "CONTROL-INJECTION-FASTAPI-DIRECT-COMMAND-001"
    assert contract.security_domain_ids == ("DOMAIN-INJECTION-001",)
