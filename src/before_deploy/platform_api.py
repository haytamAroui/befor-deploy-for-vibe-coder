"""Transport-neutral programmatic facade over the canonical Before Deploy CLI contracts."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, replace
from io import StringIO
from json import JSONDecodeError, loads
from typing import Any, Sequence

from before_deploy.release_entrypoint import main as release_main

PLATFORM_API_SCHEMA_VERSION = 1
PLATFORM_API_STATUS_COMPLETED = "COMPLETED"
PLATFORM_API_STATUS_NONZERO_EXIT = "NONZERO_EXIT"
DEFAULT_MAX_CAPTURE_CHARS = 2_000_000

CAPABILITY_DETERMINISTIC_GATE = "DETERMINISTIC_GATE"
CAPABILITY_ADVISORY_REVIEW = "ADVISORY_REVIEW"
CAPABILITY_DIAGNOSTIC = "DIAGNOSTIC"
CAPABILITY_ADVISORY_WORKFLOW = "ADVISORY_WORKFLOW"
CAPABILITY_HUMAN_GOVERNANCE = "HUMAN_GOVERNANCE"
CAPABILITY_PATCH_GENERATION = "PATCH_GENERATION"
CAPABILITY_WORKSPACE_MUTATION = "WORKSPACE_MUTATION"
CAPABILITY_DETERMINISTIC_EVIDENCE = "DETERMINISTIC_EVIDENCE"
CAPABILITY_RELEASE_AUTHORITY = "RELEASE_AUTHORITY"

_OPERATION_CAPABILITIES = {
    "scan": CAPABILITY_DETERMINISTIC_GATE,
    "review": CAPABILITY_ADVISORY_REVIEW,
    "benchmark": CAPABILITY_DIAGNOSTIC,
    "inspect": CAPABILITY_DIAGNOSTIC,
    "investigate": CAPABILITY_ADVISORY_WORKFLOW,
    "explain": CAPABILITY_ADVISORY_WORKFLOW,
    "propose": CAPABILITY_ADVISORY_WORKFLOW,
    "approve": CAPABILITY_HUMAN_GOVERNANCE,
    "fix": CAPABILITY_PATCH_GENERATION,
    "regress": CAPABILITY_WORKSPACE_MUTATION,
    "verify": CAPABILITY_DETERMINISTIC_EVIDENCE,
    "history": CAPABILITY_DETERMINISTIC_EVIDENCE,
    "release": CAPABILITY_RELEASE_AUTHORITY,
}

_GOVERNANCE_OPERATIONS = frozenset({"approve", "fix"})
_WORKSPACE_MUTATION_OPERATIONS = frozenset({"regress"})
MCP_DEFAULT_OPERATIONS = (
    "inspect",
    "investigate",
    "explain",
    "propose",
    "verify",
    "history",
    "release",
)


@dataclass(frozen=True)
class PlatformApiPolicy:
    """Transport policy; it never changes domain authority or gate semantics."""

    allow_governance: bool = False
    allow_workspace_mutation: bool = False
    max_capture_chars: int = DEFAULT_MAX_CAPTURE_CHARS


@dataclass(frozen=True)
class PlatformApiResult:
    """One in-process CLI execution envelope."""

    schema_version: int
    operation: str
    capability: str
    status: str
    exit_code: int
    stdout: str
    stderr: str
    payload: Any | None = None


class BeforeDeployPlatformAPI:
    """Call canonical Before Deploy commands without reproducing their domain logic."""

    def __init__(self, *, policy: PlatformApiPolicy | None = None) -> None:
        self.policy = policy or PlatformApiPolicy()
        if self.policy.max_capture_chars <= 0:
            raise ValueError("Platform API capture limit must be positive")

    def capabilities(self) -> dict[str, Any]:
        """Return the transport capability map without implying release authority."""
        return {
            "schema_version": PLATFORM_API_SCHEMA_VERSION,
            "operations": [
                {
                    "name": name,
                    "capability": capability,
                    "enabled": self._operation_enabled(name),
                    "mcp_default_exposed": name in MCP_DEFAULT_OPERATIONS,
                }
                for name, capability in _OPERATION_CAPABILITIES.items()
            ],
            "policy": {
                "allow_governance": self.policy.allow_governance,
                "allow_workspace_mutation": self.policy.allow_workspace_mutation,
            },
            "authority_contract": {
                "transport_only": True,
                "release_authority_operation": "release",
                "mcp_governance_exposed": False,
                "mcp_workspace_mutation_exposed": False,
            },
        }

    def execute(self, operation: str, arguments: Sequence[str]) -> PlatformApiResult:
        """Execute one canonical command through the installed entrypoint chain."""
        operation = _validate_operation(operation)
        self._require_enabled(operation)
        args = _validate_arguments(arguments)
        stdout_buffer = StringIO()
        stderr_buffer = StringIO()
        exit_code = 0
        try:
            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exit_code = release_main([operation, *args])
        except SystemExit as error:
            exit_code = _system_exit_code(error.code)

        stdout = stdout_buffer.getvalue()
        stderr = stderr_buffer.getvalue()
        self._check_capture(stdout, "stdout")
        self._check_capture(stderr, "stderr")
        return PlatformApiResult(
            schema_version=PLATFORM_API_SCHEMA_VERSION,
            operation=operation,
            capability=_OPERATION_CAPABILITIES[operation],
            status=(
                PLATFORM_API_STATUS_COMPLETED
                if exit_code == 0
                else PLATFORM_API_STATUS_NONZERO_EXIT
            ),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def execute_json(self, operation: str, arguments: Sequence[str]) -> PlatformApiResult:
        """Execute a JSON-rendering command and parse only the canonical stdout payload."""
        args = _validate_arguments(arguments)
        if any(value == "--format" or value.startswith("--format=") for value in args):
            raise ValueError("Platform JSON execution owns the --format argument")
        result = self.execute(operation, [*args, "--format", "json"])
        if not result.stdout.strip():
            return result
        try:
            payload = loads(result.stdout)
        except JSONDecodeError as error:
            if result.exit_code == 0:
                raise ValueError("Canonical command returned non-JSON output in JSON mode") from error
            return result
        if not isinstance(payload, (dict, list)):
            raise ValueError("Canonical JSON output must be an object or array")
        return replace(result, status=PLATFORM_API_STATUS_COMPLETED, payload=payload)

    def _operation_enabled(self, operation: str) -> bool:
        if operation in _GOVERNANCE_OPERATIONS:
            return self.policy.allow_governance
        if operation in _WORKSPACE_MUTATION_OPERATIONS:
            return self.policy.allow_workspace_mutation
        return True

    def _require_enabled(self, operation: str) -> None:
        if self._operation_enabled(operation):
            return
        if operation in _GOVERNANCE_OPERATIONS:
            raise PermissionError(
                f"Platform API operation {operation!r} requires explicit governance enablement"
            )
        raise PermissionError(
            f"Platform API operation {operation!r} requires explicit workspace-mutation enablement"
        )

    def _check_capture(self, value: str, label: str) -> None:
        if len(value) > self.policy.max_capture_chars:
            raise ValueError(
                f"Platform API {label} exceeded capture limit: "
                f"{len(value)} > {self.policy.max_capture_chars} characters"
            )


def platform_api_result_to_primitive(result: PlatformApiResult) -> dict[str, Any]:
    """Render the transport envelope without reinterpreting its canonical payload."""
    return {
        "schema_version": result.schema_version,
        "operation": result.operation,
        "capability": result.capability,
        "status": result.status,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "payload": result.payload,
    }


def _validate_operation(operation: str) -> str:
    if not isinstance(operation, str) or not operation or operation != operation.strip():
        raise ValueError("Platform API operation must be non-empty canonical text")
    if operation not in _OPERATION_CAPABILITIES:
        raise ValueError(f"Unsupported Platform API operation {operation!r}")
    return operation


def _validate_arguments(arguments: Sequence[str]) -> list[str]:
    if isinstance(arguments, (str, bytes)):
        raise TypeError("Platform API arguments must be a sequence of strings")
    values: list[str] = []
    for value in arguments:
        if not isinstance(value, str):
            raise TypeError("Platform API arguments must contain only strings")
        if "\x00" in value:
            raise ValueError("Platform API arguments may not contain NUL bytes")
        values.append(value)
    return values


def _system_exit_code(code: object) -> int:
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    return 1
