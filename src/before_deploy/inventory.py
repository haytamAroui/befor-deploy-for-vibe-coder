"""Repository discovery and reproducible input manifest creation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from subprocess import DEVNULL, CalledProcessError, run
from typing import Iterable

from before_deploy.models import ScanManifest, new_scan_id, utc_now

DEFAULT_MAX_FILE_BYTES = 1_000_000
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".sentinel",
    ".venv",
    ".vscode",
    "__pycache__",
    "artifacts",
    "coverage",
    "dist",
    "fixtures",
    "htmlcov",
    "node_modules",
    "reports",
    "venv",
}
EXCLUDED_FILE_NAMES = {".DS_Store"}


@dataclass(frozen=True)
class RepositoryInventory:
    """The bounded, deterministic file scope used by a scan."""

    root: Path
    files: tuple[Path, ...]
    excluded_file_count: int
    limitations: tuple[str, ...]


def collect_inventory(
    repository_path: Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> RepositoryInventory:
    """Collect files in deterministic order while excluding generated and secret-prone locations."""
    root = repository_path.resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {repository_path}")
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be greater than zero")

    included: list[Path] = []
    excluded_count = 0
    limitations: list[str] = [
        "Git history is not scanned in this milestone.",
        f"Files larger than {max_file_bytes} bytes are not scanned.",
    ]

    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir():
            continue
        relative = path.relative_to(root)
        if _is_excluded(relative):
            excluded_count += 1
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                excluded_count += 1
                continue
            if not path.is_file():
                excluded_count += 1
                continue
        except OSError:
            excluded_count += 1
            continue
        included.append(path)

    return RepositoryInventory(
        root=root,
        files=tuple(included),
        excluded_file_count=excluded_count,
        limitations=tuple(limitations),
    )


def compute_repository_digest(inventory: RepositoryInventory) -> str:
    """Hash the bounded input set by path and file bytes in stable order."""
    digest = sha256()
    for path in inventory.files:
        relative = path.relative_to(inventory.root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        try:
            content = path.read_bytes()
        except OSError as error:
            raise ValueError(f"Unable to read scanned file: {path}") from error
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def compute_file_digest(path: Path) -> str:
    """Hash a policy or waiver file without interpreting its content."""
    if not path.is_file():
        raise ValueError(f"Expected a file: {path}")
    return sha256(path.read_bytes()).hexdigest()


def create_manifest(
    inventory: RepositoryInventory,
    *,
    policy_path: Path,
    policy_name: str,
) -> ScanManifest:
    """Create an immutable starting manifest for the selected scan inputs."""
    return ScanManifest(
        scan_id=new_scan_id(),
        repository_path=inventory.root.as_posix(),
        repository_digest=compute_repository_digest(inventory),
        policy_digest=compute_file_digest(policy_path),
        policy_name=policy_name,
        started_at=utc_now(),
        git_revision=resolve_git_revision(inventory.root),
        scanned_file_count=len(inventory.files),
        excluded_file_count=inventory.excluded_file_count,
        limitations=inventory.limitations,
    )


def resolve_git_revision(repository_path: Path) -> str | None:
    """Return the current Git revision if the path is inside a Git worktree."""
    try:
        completed = run(
            ["git", "-C", str(repository_path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            stdin=DEVNULL,
            timeout=3,
        )
    except (CalledProcessError, FileNotFoundError, TimeoutError):
        return None
    revision = completed.stdout.strip()
    return revision or None


def relative_paths(inventory: RepositoryInventory) -> Iterable[Path]:
    """Yield scan paths relative to the inventory root."""
    return (path.relative_to(inventory.root) for path in inventory.files)


def _is_excluded(relative_path: Path) -> bool:
    return (
        relative_path.name in EXCLUDED_FILE_NAMES
        or any(part in EXCLUDED_DIRECTORY_NAMES for part in relative_path.parts[:-1])
    )
