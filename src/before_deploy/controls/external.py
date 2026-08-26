"""Isolated process execution primitives for untrusted external security scanners."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExternalToolConfig:
    """Minimal, validated configuration for one scanner executable."""

    executable: str
    tool_version: str = "unspecified"
    timeout_seconds: int = 60
    max_report_bytes: int = 5_000_000

    def __post_init__(self) -> None:
        if not self.executable.strip():
            raise ValueError("External tool executable must be non-empty")
        if not self.tool_version.strip():
            raise ValueError("External tool tool_version must be non-empty")
        if self.timeout_seconds <= 0:
            raise ValueError("External tool timeout_seconds must be greater than zero")
        if self.max_report_bytes <= 0:
            raise ValueError("External tool max_report_bytes must be greater than zero")


@dataclass(frozen=True)
class ExternalToolRun:
    """Redaction-safe process outcome that deliberately excludes stdout and stderr."""

    executable: str
    return_code: int | None
    timed_out: bool
    error_kind: str | None = None

    @property
    def completed(self) -> bool:
        return self.error_kind is None and not self.timed_out and self.return_code is not None


class ExternalToolRunner:
    """Invoke an allowlisted executable without shell expansion or inherited secrets."""

    def run(
        self,
        *,
        config: ExternalToolConfig,
        arguments: tuple[str, ...],
        cwd: Path,
        stdout_path: Path | None = None,
    ) -> ExternalToolRun:
        """Run a tool with a minimal environment and a bounded wall-clock timeout."""
        executable = _resolve_executable(config.executable)
        if executable is None:
            return ExternalToolRun(
                executable=config.executable,
                return_code=None,
                timed_out=False,
                error_kind="EXECUTABLE_NOT_FOUND",
            )
        if not cwd.is_dir():
            return ExternalToolRun(
                executable=executable,
                return_code=None,
                timed_out=False,
                error_kind="INVALID_WORKING_DIRECTORY",
            )

        with tempfile.TemporaryDirectory(prefix="before-deploy-tool-home-") as tool_home:
            environment = _minimal_environment(Path(tool_home))
            try:
                if stdout_path is None:
                    completed = subprocess.run(
                        [executable, *arguments],
                        cwd=cwd,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=config.timeout_seconds,
                    )
                else:
                    stdout_path.parent.mkdir(parents=True, exist_ok=True)
                    with stdout_path.open("wb") as stdout_file:
                        completed = subprocess.run(
                            [executable, *arguments],
                            cwd=cwd,
                            env=environment,
                            stdin=subprocess.DEVNULL,
                            stdout=stdout_file,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=config.timeout_seconds,
                        )
            except subprocess.TimeoutExpired:
                return ExternalToolRun(
                    executable=executable,
                    return_code=None,
                    timed_out=True,
                    error_kind="TIMEOUT",
                )
            except OSError:
                return ExternalToolRun(
                    executable=executable,
                    return_code=None,
                    timed_out=False,
                    error_kind="PROCESS_START_FAILED",
                )
        return ExternalToolRun(
            executable=executable,
            return_code=completed.returncode,
            timed_out=False,
        )


def read_bounded_report(path: Path, max_bytes: int) -> bytes:
    """Read a temporary report only when its size is explicitly bounded."""
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError("External scanner did not produce a readable report") from error
    if size > max_bytes:
        raise ValueError("External scanner report exceeded the configured size limit")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError("External scanner report could not be read") from error


def _resolve_executable(requested: str) -> str | None:
    candidate = Path(requested)
    if candidate.parent != Path("."):
        return candidate.resolve().as_posix() if candidate.is_file() else None
    return shutil.which(requested)


def _minimal_environment(tool_home: Path) -> dict[str, str]:
    path = os.environ.get("PATH", "")
    return {
        "HOME": tool_home.as_posix(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": path,
        "TERM": "dumb",
    }
