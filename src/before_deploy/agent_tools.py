"""Policy and registry for deterministic read-only advisory-agent tools."""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_AGENT_TOOLS = frozenset(
    {
        "read_file",
        "search_text",
        "search_symbol",
        "find_references",
        "find_callers",
        "find_tests",
        "dependency_neighbors",
    }
)


@dataclass(frozen=True)
class RepositoryToolPolicy:
    """Authorization and output bounds for deterministic repository exploration."""

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
