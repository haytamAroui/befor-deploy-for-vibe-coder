"""Narrow deterministic Go controls with explicit static-analysis boundaries."""

from __future__ import annotations

import re

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.models import (
    Confidence,
    ControlExecution,
    ExecutionStatus,
    Finding,
    Location,
    Severity,
    fingerprint_for,
    utc_now,
)

_MODULE_REQUIRE_DIRECTIVE = re.compile(r"^\s*require\s+\S+\s+\S+", re.MULTILINE)
_MODULE_REQUIRE_BLOCK = re.compile(r"^\s*require\s*\((?P<body>.*?)^\s*\)", re.MULTILINE | re.DOTALL)
_TLS_CONFIG_START = re.compile(r"(?<![\w*.])&?\s*tls\.Config\s*\{")
_INSECURE_SKIP_VERIFY = re.compile(r"\bInsecureSkipVerify\s*:\s*true\b")


class GoModuleIntegrityControl:
    """Require go.sum only when a root Go module declares dependencies."""

    control_id = "SEC-GO-MODULE-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        root_files = {
            path.relative_to(context.repository_root).as_posix(): path
            for path in context.inventory.files
        }
        module_path = root_files.get("go.mod")
        if module_path is None:
            return _not_applicable(
                self,
                started_at,
                "No root go.mod manifest was detected for the Go module-integrity check.",
            )
        try:
            module_text = module_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return _error_result(self, started_at, "MODULE_MANIFEST_UNREADABLE")
        has_dependencies = _has_declared_dependencies(module_text)
        findings: tuple[Finding, ...] = ()
        if has_dependencies and "go.sum" not in root_files:
            evidence = {"ecosystem": "go", "issue": "go_sum_missing"}
            location = Location(path="go.mod", start_line=1)
            findings = (
                Finding(
                    rule_id=self.control_id,
                    rule_version=self.control_version,
                    title="Go dependency checksum file is missing",
                    message=(
                        "The root go.mod declares dependencies but the repository has no root go.sum "
                        "checksum file."
                    ),
                    remediation=(
                        "Generate and commit go.sum using the Go toolchain in a reviewed dependency "
                        "update workflow, then use locked module behavior in CI."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    fingerprint=fingerprint_for(self.control_id, location, evidence),
                    location=location,
                    evidence=evidence,
                ),
            )
        message = (
            "Inspected root go.mod dependency declarations and root go.sum presence."
            if has_dependencies
            else "Root go.mod declares no dependencies; go.sum is not required by this narrow check."
        )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=message,
            ),
            findings=findings,
        )


class GoTLSVerificationControl:
    """Detect direct tls.Config literals that explicitly disable certificate verification."""

    control_id = "SEC-GO-TLS-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        findings: list[Finding] = []
        for path in context.inventory.files:
            if path.suffix.lower() != ".go":
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return _error_result(self, started_at, "GO_SOURCE_UNREADABLE")
            sanitized = _strip_go_comments_and_strings(source)
            for offset in _insecure_tls_offsets(sanitized):
                relative_path = path.relative_to(context.repository_root).as_posix()
                location = Location(
                    path=relative_path,
                    start_line=sanitized.count("\n", 0, offset) + 1,
                )
                evidence = {"issue": "tls_insecure_skip_verify_literal"}
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Go TLS certificate verification is explicitly disabled",
                        message=(
                            "A direct tls.Config composite literal explicitly sets InsecureSkipVerify to "
                            "true. The source excerpt is intentionally not retained."
                        ),
                        remediation=(
                            "Enable certificate and hostname verification. If a custom verification flow is "
                            "required, document and test it before using a narrowly scoped policy waiver."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Inspected direct Go tls.Config literals for explicit disabled verification.",
            ),
            findings=tuple(findings),
        )


def _has_declared_dependencies(module_text: str) -> bool:
    """Recognize only direct and block-form require directives in a root go.mod file."""
    without_comments = "\n".join(line.split("//", 1)[0] for line in module_text.splitlines())
    if _MODULE_REQUIRE_DIRECTIVE.search(without_comments):
        return True
    for match in _MODULE_REQUIRE_BLOCK.finditer(without_comments):
        if any(line.strip() and not line.lstrip().startswith("//") for line in match.group("body").splitlines()):
            return True
    return False


def _insecure_tls_offsets(source: str) -> tuple[int, ...]:
    """Return only direct literal offsets; aliases, variables, and computed values are excluded."""
    offsets: list[int] = []
    for match in _TLS_CONFIG_START.finditer(source):
        body_end = _balanced_literal_end(source, match.end() - 1)
        if body_end is None:
            continue
        insecure = _INSECURE_SKIP_VERIFY.search(source, match.end(), body_end)
        if insecure is not None:
            offsets.append(insecure.start())
    return tuple(offsets)


def _balanced_literal_end(source: str, opening_brace_offset: int) -> int | None:
    depth = 0
    for index in range(opening_brace_offset, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _strip_go_comments_and_strings(source: str) -> str:
    """Blank comments and string literals while preserving offsets and newlines for line locations."""
    result: list[str] = []
    index = 0
    state = "code"
    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""
        if state == "code" and character == "/" and next_character == "/":
            state = "line_comment"
            result.extend((" ", " "))
            index += 2
            continue
        if state == "code" and character == "/" and next_character == "*":
            state = "block_comment"
            result.extend((" ", " "))
            index += 2
            continue
        if state == "code" and character == '"':
            state = "quoted_string"
            result.append(" ")
            index += 1
            continue
        if state == "code" and character == "`":
            state = "raw_string"
            result.append(" ")
            index += 1
            continue
        if state == "line_comment":
            result.append("\n" if character == "\n" else " ")
            if character == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and next_character == "/":
                result.extend((" ", " "))
                index += 2
                state = "code"
                continue
            result.append("\n" if character == "\n" else " ")
            index += 1
            continue
        if state == "quoted_string":
            result.append("\n" if character == "\n" else " ")
            if character == "\\" and index + 1 < len(source):
                result.append("\n" if next_character == "\n" else " ")
                index += 2
                continue
            if character == '"':
                state = "code"
            index += 1
            continue
        if state == "raw_string":
            result.append("\n" if character == "\n" else " ")
            if character == "`":
                state = "code"
            index += 1
            continue
        result.append(character)
        index += 1
    return "".join(result)


def _not_applicable(control, started_at, message: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=False,
            message=message,
        )
    )


def _error_result(control, started_at, error_kind: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=control.control_id,
            control_version=control.control_version,
            status=ExecutionStatus.ERROR,
            started_at=started_at,
            completed_at=utc_now(),
            message=f"Go control error: {error_kind}",
            metadata={"error_kind": error_kind},
        )
    )
