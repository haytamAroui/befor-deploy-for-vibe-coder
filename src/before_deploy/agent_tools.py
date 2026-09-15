"""Deterministic read-only repository tools for native advisory agents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from before_deploy.agent_runtime import AgentToolRequest, AgentToolResult

ALLOWED_AGENT_TOOLS = frozenset({"read_file", "search_text", "search_symbol", "find_references", "find_callers", "find_tests", "dependency_neighbors"})


@dataclass(frozen=True)
class RepositoryToolPolicy:
    allowed_tools: frozenset[str] = ALLOWED_AGENT_TOOLS
    allow_scope_expansion: bool = True
    max_file_bytes: int = 1_000_000
    max_results: int = 40
    max_read_lines: int = 800

    def validate(self) -> None:
        if not self.allowed_tools or not self.allowed_tools <= ALLOWED_AGENT_TOOLS:
            raise ValueError("Repository agent policy contains unsupported tools")
        for name in ("max_file_bytes", "max_results", "max_read_lines"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"Repository agent policy {name} must be positive")


class RepositoryToolExecutor:
    """Base read-only tool executor. Concrete indexing/search support is added in this PR."""

    def __init__(self, repository: Path, *, policy: RepositoryToolPolicy | None = None) -> None:
        self.root = repository.resolve()
        self.policy = policy or RepositoryToolPolicy()
        self.policy.validate()
        if not self.root.is_dir():
            raise ValueError("Repository path must be a directory")

    def execute(self, request: AgentToolRequest, *, max_bytes: int) -> AgentToolResult:
        if request.tool_name not in self.policy.allowed_tools:
            return AgentToolResult.from_text(
                call_id=request.call_id,
                tool_name=request.tool_name,
                status="DENIED",
                content="tool_not_allowed",
                message="tool_not_allowed",
            )
        return AgentToolResult.from_text(
            call_id=request.call_id,
            tool_name=request.tool_name,
            status="ERROR",
            content="tool_not_implemented",
            message="tool_not_implemented",
        )
