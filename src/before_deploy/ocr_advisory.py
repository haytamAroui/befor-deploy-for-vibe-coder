"""Opt-in isolated OpenCodeReview execution for the advisory review plane."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from shutil import which
from subprocess import DEVNULL, TimeoutExpired, run
from tempfile import TemporaryDirectory

from before_deploy.advisory import AdvisoryImport, advisory_error_import, load_advisory_file

OCR_SOURCE = "open-code-review"
OCR_SOURCE_FORMAT = "ocr-json"


@dataclass(frozen=True)
class OcrAdvisoryOptions:
    """Bounded execution options for the reviewed OCR advisory adapter."""

    timeout_seconds: int = 900
    max_output_bytes: int = 2_000_000
    from_ref: str | None = None
    to_ref: str | None = None
    commit: str | None = None


def run_ocr_advisory(repository: Path, options: OcrAdvisoryOptions) -> AdvisoryImport:
    """Run OCR with fixed arguments and return gate-neutral advisory evidence."""
    validation_error = _validate_options(options)
    if validation_error is not None:
        return _error(validation_error)

    executable = which("ocr")
    if executable is None:
        return _error("OpenCodeReview executable `ocr` was not found on PATH")

    repository = repository.resolve()
    with TemporaryDirectory(prefix="before-deploy-ocr-") as temp_dir:
        output_path = Path(temp_dir) / "ocr-review.json"
        stderr_path = Path(temp_dir) / "ocr-stderr.log"
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
        if options.commit:
            command.extend(["--commit", options.commit])
        elif options.from_ref and options.to_ref:
            command.extend(["--from", options.from_ref, "--to", options.to_ref])

        try:
            with stderr_path.open("wb") as stderr_file:
                completed = run(
                    command,
                    stdin=DEVNULL,
                    stdout=DEVNULL,
                    stderr=stderr_file,
                    timeout=options.timeout_seconds,
                    check=False,
                )
        except TimeoutExpired:
            return _error(
                f"OpenCodeReview exceeded the advisory timeout of {options.timeout_seconds} seconds"
            )
        except OSError as error:
            return _error(f"OpenCodeReview could not start: {type(error).__name__}")

        if completed.returncode != 0:
            return _error(f"OpenCodeReview exited with code {completed.returncode}")
        if not output_path.is_file():
            return _error("OpenCodeReview completed without producing the expected JSON output")

        try:
            output_size = output_path.stat().st_size
        except OSError as error:
            return _error(f"OpenCodeReview output could not be inspected: {type(error).__name__}")
        if output_size > options.max_output_bytes:
            return _error(
                "OpenCodeReview output exceeded the advisory size limit "
                f"of {options.max_output_bytes} bytes"
            )

        try:
            imported = load_advisory_file(output_path)
        except (OSError, ValueError) as error:
            return _error(f"OpenCodeReview output was unusable: {type(error).__name__}")
        return replace(imported, input_name="ocr", source=OCR_SOURCE, source_format=OCR_SOURCE_FORMAT)


def _validate_options(options: OcrAdvisoryOptions) -> str | None:
    if options.timeout_seconds <= 0:
        return "OCR advisory timeout must be greater than zero"
    if options.max_output_bytes <= 0:
        return "OCR advisory output limit must be greater than zero"
    if bool(options.from_ref) != bool(options.to_ref):
        return "OCR --from and --to must be supplied together"
    if options.commit and (options.from_ref or options.to_ref):
        return "OCR commit mode cannot be combined with --from/--to"
    return None


def _error(message: str) -> AdvisoryImport:
    return advisory_error_import(
        input_name="ocr",
        source=OCR_SOURCE,
        source_format=OCR_SOURCE_FORMAT,
        message=message,
    )
