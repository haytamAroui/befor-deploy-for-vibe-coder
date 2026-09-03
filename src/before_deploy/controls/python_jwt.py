"""Bounded Python JWT signature-verification control."""

from __future__ import annotations

import ast

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

_CONTROL_ID = "SEC-JWT-PYTHON-VERIFY-001"
_CONTROL_VERSION = "0.1.0"


class PythonJwtSignatureVerificationControl:
    """Flag direct JWT decode calls that explicitly disable signature verification.

    Supported imports are intentionally narrow: direct ``import jwt``, ``from jwt import decode``,
    ``from jose import jwt``, or ``from jose.jwt import decode`` without aliases. A finding is emitted
    only when the same file contains a supported direct decode call whose literal ``options`` mapping
    sets ``verify_signature`` to ``False``. Import aliases, helper wrappers, options stored in variables,
    dictionary expansion, alternative JWT libraries, algorithm choice, expiry validation, key
    management, revocation, storage, and runtime behavior are excluded.
    """

    control_id = _CONTROL_ID
    control_version = _CONTROL_VERSION

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = sorted(path for path in context.inventory.files if path.suffix == ".py")
        if not python_files:
            return _not_applicable(started_at, "No Python source files were in scope.")

        findings: list[Finding] = []
        applicable = False
        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read Python JWT source: {relative}") from error
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError:
                continue

            module_decode, direct_decode = _supported_imports(tree)
            if not module_decode and not direct_decode:
                continue
            applicable = True

            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                if not _is_supported_decode_call(call, module_decode, direct_decode):
                    continue
                if not _disables_signature_verification(call):
                    continue
                location = Location(path=relative, start_line=getattr(call, "lineno", 1))
                evidence = {
                    "artifact": "python_source",
                    "flow": "jwt_decode_literal_options_verify_signature_false",
                    "verification": "signature_disabled",
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="JWT decode explicitly disables signature verification",
                        message=(
                            "A supported Python JWT decode call sets options.verify_signature to False, "
                            "so token signatures are not cryptographically verified by that call."
                        ),
                        remediation=(
                            "Require signature verification with an explicitly trusted key and reviewed "
                            "algorithm allowlist. Review expiry, issuer, audience, key rotation, revocation, "
                            "and token storage separately."
                        ),
                        severity=Severity.BLOCKER,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )

        if not applicable:
            return _not_applicable(
                started_at,
                "No supported direct PyJWT or python-jose import was detected.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message=(
                    "Checked supported direct Python JWT decode calls for literal signature-verification "
                    "disablement."
                ),
            ),
            findings=tuple(findings),
        )


def _supported_imports(tree: ast.Module) -> tuple[bool, bool]:
    module_decode = False
    direct_decode = False
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "jwt" and alias.asname is None:
                    module_decode = True
        elif isinstance(node, ast.ImportFrom):
            if node.module == "jose":
                if any(alias.name == "jwt" and alias.asname is None for alias in node.names):
                    module_decode = True
            elif node.module in {"jwt", "jose.jwt"}:
                if any(alias.name == "decode" and alias.asname is None for alias in node.names):
                    direct_decode = True
    return module_decode, direct_decode


def _is_supported_decode_call(call: ast.Call, module_decode: bool, direct_decode: bool) -> bool:
    if module_decode:
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "decode"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "jwt"
        ):
            return True
    return direct_decode and isinstance(call.func, ast.Name) and call.func.id == "decode"


def _disables_signature_verification(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg != "options" or not isinstance(keyword.value, ast.Dict):
            continue
        for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
            if (
                isinstance(key, ast.Constant)
                and key.value == "verify_signature"
                and isinstance(value, ast.Constant)
                and value.value is False
            ):
                return True
    return False


def _not_applicable(started_at, message: str) -> ControlResult:
    return ControlResult(
        execution=ControlExecution(
            control_id=_CONTROL_ID,
            control_version=_CONTROL_VERSION,
            status=ExecutionStatus.NOT_APPLICABLE,
            started_at=started_at,
            completed_at=utc_now(),
            applicable=False,
            message=message,
        )
    )
