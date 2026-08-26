"""Contracts shared by all deterministic control adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from before_deploy.inventory import RepositoryInventory
from before_deploy.models import ControlExecution, Finding


@dataclass(frozen=True)
class ControlContext:
    """Inputs provided to one control without policy decision authority."""

    repository_root: Path
    inventory: RepositoryInventory
    public_fastapi_routes: frozenset[tuple[str, str]] = frozenset()


@dataclass(frozen=True)
class ControlResult:
    """Normalized result of a single adapter execution."""

    execution: ControlExecution
    findings: tuple[Finding, ...] = ()


class Control(Protocol):
    """Protocol that native and external tool adapters must implement."""

    control_id: str
    control_version: str

    def run(self, context: ControlContext) -> ControlResult:
        """Evaluate the bounded input scope and return findings or an explicit execution state."""
