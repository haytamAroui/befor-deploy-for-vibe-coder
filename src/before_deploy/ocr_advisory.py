"""Opt-in isolated OpenCodeReview execution for the advisory review plane."""

from __future__ import annotations

from dataclasses import dataclass, replace
from json import JSONDecodeError, loads
from pathlib import Path, PurePosixPath
from shutil import which
from subprocess import DEVNULL, TimeoutExpired, run
from tempfile import TemporaryDirectory
from typing import Any, Mapping

from before_deploy.advisory import AdvisoryImport, advisory_error_import, load_advisory_file
from before_deploy.review_preview import build_review_preview

OCR_SOURCE = "open-code-review"
OCR_SOURCE_FORMAT = "ocr-json"
OCR_MANIFEST_SCHEMA = "ocr.run-manifest/v1"
OCR_PREVIEW_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class OcrAdvisoryOptions:
    """Bounded execution options for the reviewed OCR advisory adapter."""

    timeout_seconds: int = 900
    max_output_bytes: int = 2_000_000
    max_file_bytes: int = 1_000_000
    from_ref: str | None = None
    to_ref: str | None = None
    commit: str | None = None


def run_ocr_advisory(repository: Path, options: OcrAdvisoryOptions) -> AdvisoryImport:
    """Run OCR with deterministic scope checks and return gate-neutral advisory evidence."""
    validation_error = _validate_options(options)
    if validation_error is not None:
        return _error(validation_error)

    executable = which("ocr")
    if executable is None:
        return _error("OpenCodeReview executable `ocr` was not found on PATH")

    repository = repository.resolve()
    try:
        expected_preview = build_review_preview(
            repository,
            max_file_bytes=options.max_file_bytes,
            from_ref=options.from_ref,
            to_ref=options.to_ref,
            commit=options.commit,
        )
    except (OSError, ValueError) as error:
        return _error(f"Before Deploy review scope could not be resolved: {type(error).__name__}")

    allowed_paths = {entry.path for entry in expected_preview.entries if entry.will_review}
    with TemporaryDirectory(prefix="before-deploy-ocr-") as temp_dir:
        temp_root = Path(temp_dir)
        preview_path = temp_root / "ocr-preview.json"
        preview_command = _ocr_command(
            executable,
            repository,
            preview_path,
            options,
            preview=True,
        )
        preview_error = _execute(
            preview_command,
            timeout_seconds=min(options.timeout_seconds, OCR_PREVIEW_TIMEOUT_SECONDS),
            phase="preview",
        )
        if preview_error is not None:
            return _error(preview_error)

        try:
            preview_payload = _read_json(
                preview_path,
                max_output_bytes=options.max_output_bytes,
                label="preview",
            )
            provider_paths = _preview_selected_paths(preview_payload)
        except (OSError, ValueError) as error:
            return _error(f"OpenCodeReview preview was unusable: {type(error).__name__}")

        unexpected = provider_paths - allowed_paths
        if unexpected:
            return _error(
                "OpenCodeReview preview expanded beyond the Before Deploy review scope",
                scope_status="EXPANDED",
                scope_message=(
                    f"OCR selected {len(unexpected)} path(s) outside the deterministic allowed set; "
                    "the LLM review was not started"
                ),
            )

        preflight_missing = allowed_paths - provider_paths
        preflight_status = "PARTIAL" if preflight_missing else "MATCHED"
        preflight_message = _scope_message(
            allowed_count=len(allowed_paths),
            provider_count=len(provider_paths),
            missing_count=len(preflight_missing),
        )

        if not provider_paths:
            return AdvisoryImport(
                input_name="ocr",
                source=OCR_SOURCE,
                source_format=OCR_SOURCE_FORMAT,
                findings=(),
                status="COMPLETED",
                message="OpenCodeReview selected no files for advisory review",
                scope_status=preflight_status,
                scope_message=preflight_message,
            )

        output_path = temp_root / "ocr-review.json"
        review_command = _ocr_command(
            executable,
            repository,
            output_path,
            options,
            preview=False,
        )
        review_error = _execute(
            review_command,
            timeout_seconds=options.timeout_seconds,
            phase="review",
        )
        if review_error is not None:
            return _error(
                review_error,
                scope_status=preflight_status,
                scope_message=preflight_message,
            )

        try:
            review_payload = _read_json(
                output_path,
                max_output_bytes=options.max_output_bytes,
                label="review",
            )
        except (OSError, ValueError) as error:
            return _error(
                f"OpenCodeReview output was unusable: {type(error).__name__}",
                scope_status=preflight_status,
                scope_message=preflight_message,
            )

        final_paths = _manifest_selected_paths(review_payload)
        if final_paths is None:
            final_scope_status = "PREFLIGHT_ONLY"
            final_scope_message = (
                "OCR preflight scope was checked, but the final output did not expose the supported "
                f"{OCR_MANIFEST_SCHEMA} selected set"
            )
        else:
            final_unexpected = final_paths - allowed_paths
            if final_unexpected:
                return _error(
                    "OpenCodeReview final manifest expanded beyond the Before Deploy review scope",
                    scope_status="EXPANDED",
                    scope_message=(
                        f"The final OCR manifest selected {len(final_unexpected)} path(s) outside "
                        "the deterministic allowed set; OCR findings were discarded"
                    ),
                )
            if final_paths != provider_paths:
                return _error(
                    "OpenCodeReview selected-file set drifted after preflight",
                    scope_status="DRIFT",
                    scope_message=(
                        "The OCR final manifest did not match its preflight selected set; "
                        "OCR findings were discarded"
                    ),
                )
            final_missing = allowed_paths - final_paths
            final_scope_status = "PARTIAL" if final_missing else "MATCHED"
            final_scope_message = _scope_message(
                allowed_count=len(allowed_paths),
                provider_count=len(final_paths),
                missing_count=len(final_missing),
            )

        try:
            imported = load_advisory_file(output_path)
        except (OSError, ValueError) as error:
            return _error(
                f"OpenCodeReview findings could not be normalized: {type(error).__name__}",
                scope_status=final_scope_status,
                scope_message=final_scope_message,
            )
        return replace(
            imported,
            input_name="ocr",
            source=OCR_SOURCE,
            source_format=OCR_SOURCE_FORMAT,
            scope_status=final_scope_status,
            scope_message=final_scope_message,
        )


def _ocr_command(
    executable: str,
    repository: Path,
    output_path: Path,
    options: OcrAdvisoryOptions,
    *,
    preview: bool,
) -> list[str]:
    command = [
        executable,
        "review",
        "--repo",
        str(repository),
        "--audience",
        "agent",
        "--format",
        "json",
        "--output",
        str(output_path),
    ]
    if preview:
        command.append("--preview")
    if options.commit:
        command.extend(["--commit", options.commit])
    elif options.from_ref and options.to_ref:
        command.extend(["--from", options.from_ref, "--to", options.to_ref])
    return command


def _execute(command: list[str], *, timeout_seconds: int, phase: str) -> str | None:
    try:
        completed = run(
            command,
            stdin=DEVNULL,
            stdout=DEVNULL,
            stderr=DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except TimeoutExpired:
        return f"OpenCodeReview {phase} exceeded the advisory timeout of {timeout_seconds} seconds"
    except OSError as error:
        return f"OpenCodeReview {phase} could not start: {type(error).__name__}"
    if completed.returncode != 0:
        return f"OpenCodeReview {phase} exited with code {completed.returncode}"
    return None


def _read_json(path: Path, *, max_output_bytes: int, label: str) -> Any:
    if not path.is_file():
        raise ValueError(f"OpenCodeReview {label} produced no JSON output")
    try:
        output_size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"OpenCodeReview {label} output could not be inspected") from error
    if output_size > max_output_bytes:
        raise ValueError(
            f"OpenCodeReview {label} output exceeded the accepted size limit of "
            f"{max_output_bytes} bytes"
        )
    try:
        return loads(path.read_text(encoding="utf-8"))
    except (OSError, JSONDecodeError) as error:
        raise ValueError(f"OpenCodeReview {label} output was not valid JSON") from error


def _preview_selected_paths(payload: Any) -> set[str]:
    if not isinstance(payload, Mapping):
        raise ValueError("OCR preview JSON must be an object")
    files = payload.get("files")
    if not isinstance(files, list):
        raise ValueError("OCR preview JSON has no files array")
    selected: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping):
            raise ValueError("OCR preview file entries must be objects")
        if item.get("will_review") is not True:
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            raise ValueError("OCR preview selected entry has no path")
        selected.add(_safe_relative_path(raw_path))
    return selected


def _manifest_selected_paths(payload: Any) -> set[str] | None:
    if not isinstance(payload, Mapping):
        return None
    manifest = payload.get("manifest")
    if not isinstance(manifest, Mapping):
        return None
    if manifest.get("schema_version") != OCR_MANIFEST_SCHEMA:
        return None
    coverage = manifest.get("coverage")
    if not isinstance(coverage, Mapping):
        raise ValueError("OCR manifest coverage is malformed")
    selected_items = coverage.get("selected")
    if not isinstance(selected_items, list):
        raise ValueError("OCR manifest selected coverage is malformed")
    selected: set[str] = set()
    for item in selected_items:
        if not isinstance(item, Mapping):
            raise ValueError("OCR manifest selected item is malformed")
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            raise ValueError("OCR manifest selected item has no path")
        selected.add(_safe_relative_path(raw_path))
    return selected


def _safe_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("OCR scope path must be repository-relative")
    if len(normalized) >= 3 and normalized[1:3] == ":/":
        raise ValueError("OCR scope path must not be an absolute drive path")
    return candidate.as_posix()


def _scope_message(*, allowed_count: int, provider_count: int, missing_count: int) -> str:
    if missing_count:
        return (
            f"Before Deploy allowed {allowed_count} path(s); OCR selected {provider_count}; "
            f"{missing_count} allowed path(s) were not selected by OCR"
        )
    return f"Before Deploy and OCR selected the same {allowed_count} reviewable path(s)"


def _validate_options(options: OcrAdvisoryOptions) -> str | None:
    if options.timeout_seconds <= 0:
        return "OCR advisory timeout must be greater than zero"
    if options.max_output_bytes <= 0:
        return "OCR advisory output limit must be greater than zero"
    if options.max_file_bytes <= 0:
        return "OCR review scope max_file_bytes must be greater than zero"
    if bool(options.from_ref) != bool(options.to_ref):
        return "OCR --from and --to must be supplied together"
    if options.commit and (options.from_ref or options.to_ref):
        return "OCR commit mode cannot be combined with --from/--to"
    return None


def _error(
    message: str,
    *,
    scope_status: str = "NOT_CHECKED",
    scope_message: str | None = None,
) -> AdvisoryImport:
    return advisory_error_import(
        input_name="ocr",
        source=OCR_SOURCE,
        source_format=OCR_SOURCE_FORMAT,
        message=message,
        scope_status=scope_status,
        scope_message=scope_message,
    )
