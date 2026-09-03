"""Bounded controls that close the remaining foundational security-domain mappings."""

from __future__ import annotations

import ast
import re

from before_deploy.controls.base import ControlContext, ControlResult
from before_deploy.controls.fastapi_input import FastApiInputValidationControl
from before_deploy.controls.fastapi_routes import FastApiRouteAuthenticationControl
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


class FastApiAuthenticationBoundaryControl(FastApiRouteAuthenticationControl):
    """Reuse the reviewed FastAPI route-authentication parser as an Authentication-domain contract."""

    control_id = "SEC-AUTH-FASTAPI-001"
    control_version = "0.1.0"


class FastApiEndpointAccessControl(FastApiRouteAuthenticationControl):
    """Reuse the same bounded endpoint-access predicate for the Endpoint Security domain."""

    control_id = "SEC-ENDPOINT-FASTAPI-001"
    control_version = "0.1.0"


class FastApiApiAssuranceControl(FastApiInputValidationControl):
    """Reuse the reviewed FastAPI body-typing predicate as an API-assurance contract."""

    control_id = "SEC-API-ASSURANCE-FASTAPI-001"
    control_version = "0.1.0"


class PythonDatabaseTransportControl:
    """Detect literal Python database-client configurations that explicitly disable TLS."""

    control_id = "SEC-DATABASE-TRANSPORT-PYTHON-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = sorted(path for path in context.inventory.files if path.suffix == ".py")
        if not python_files:
            return _not_applicable(self, started_at, "No Python source files were in scope.")

        supported_client_seen = False
        findings: list[Finding] = []
        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, SyntaxError) as error:
                raise ValueError(f"Unable to parse Python source: {relative}") from error

            imported = _database_imports(tree)
            if imported:
                supported_client_seen = True
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                client = _database_call_client(node, imported)
                if client is None:
                    continue
                supported_client_seen = True
                issue = _disabled_database_tls(node)
                if issue is None:
                    continue
                location = Location(path=relative, start_line=node.lineno)
                evidence = {
                    "artifact": "python_database_client_call",
                    "client": client,
                    "transport_policy": "tls_disabled",
                    "configuration_form": issue,
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Database client explicitly disables TLS",
                        message=(
                            "A supported Python database client is configured with a literal option that "
                            "disables TLS for the database connection."
                        ),
                        remediation=(
                            "Require TLS for database connections and validate the server certificate using "
                            "the database driver's supported secure transport configuration."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )

        if not supported_client_seen:
            return _not_applicable(
                self,
                started_at,
                "No supported SQLAlchemy, psycopg, or psycopg2 database-client evidence was detected.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked literal supported Python database-client TLS configuration.",
            ),
            findings=tuple(findings),
        )


class SecurityTestEvidenceControl:
    """Check for one bounded class of repository-local dedicated security-test evidence."""

    control_id = "SEC-SECURITY-TESTING-EVIDENCE-001"
    control_version = "0.1.0"

    _TEST_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".java"}
    _SECURITY_TOKENS = ("security", "auth", "authorization", "injection", "ssrf", "xss", "csrf")

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        source_files = [
            path for path in context.inventory.files if path.suffix.lower() in self._TEST_SUFFIXES
        ]
        if not source_files:
            return _not_applicable(self, started_at, "No supported application source files were in scope.")

        security_tests = []
        for path in source_files:
            relative = path.relative_to(context.repository_root).as_posix().lower()
            name = path.name.lower()
            looks_like_test = (
                "/tests/" in f"/{relative}"
                or name.startswith("test_")
                or ".test." in name
                or ".spec." in name
                or name.endswith("test.java")
                or name.endswith("tests.java")
            )
            if looks_like_test and any(token in relative for token in self._SECURITY_TOKENS):
                security_tests.append(relative)

        if security_tests:
            return ControlResult(
                execution=ControlExecution(
                    control_id=self.control_id,
                    control_version=self.control_version,
                    status=ExecutionStatus.COMPLETED,
                    started_at=started_at,
                    completed_at=utc_now(),
                    message="Detected bounded repository-local dedicated security-test evidence.",
                    metadata={"security_test_evidence": "present", "matched_file_count": str(len(security_tests))},
                )
            )

        location = Location(path=".", start_line=1)
        evidence = {
            "artifact": "repository_test_inventory",
            "security_test_evidence": "not_detected",
            "scope": "bounded_filename_and_path_patterns",
        }
        finding = Finding(
            rule_id=self.control_id,
            rule_version=self.control_version,
            title="No dedicated security-test evidence detected in the bounded repository inventory",
            message=(
                "No supported test file whose path or filename identifies a dedicated security test was "
                "detected by this bounded evidence check."
            ),
            remediation=(
                "Add focused security regression tests for relevant risks and keep them in a clearly "
                "identifiable test location so the assurance evidence is reviewable."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            fingerprint=fingerprint_for(self.control_id, location, evidence),
            location=location,
            evidence=evidence,
        )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked bounded repository-local dedicated security-test evidence.",
                metadata={"security_test_evidence": "not_detected"},
            ),
            findings=(finding,),
        )


class FastApiStripeWebhookSignatureControl:
    """Flag a narrow Stripe/FastAPI webhook form with no direct signature verification call."""

    control_id = "SEC-PAYMENT-STRIPE-WEBHOOK-001"
    control_version = "0.1.0"

    _POST_WEBHOOK = re.compile(
        r"@(?:app|router)\.post\s*\(\s*[\"'][^\"']*webhook[^\"']*[\"'][^)]*\)\s*\n\s*"
        r"(?:async\s+)?def\s+[A-Za-z_$][\w$]*\s*\([^)]*\)\s*:\s*(?P<body>(?:\n[ \t]+[^\n]*)+)",
        re.IGNORECASE,
    )
    _VERIFY = re.compile(r"\bstripe\s*\.\s*Webhook\s*\.\s*construct_event\s*\(")

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        python_files = sorted(path for path in context.inventory.files if path.suffix == ".py")
        stripe_seen = False
        supported_webhook_seen = False
        findings: list[Finding] = []

        for path in python_files:
            relative = path.relative_to(context.repository_root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as error:
                raise ValueError(f"Unable to read Python source: {relative}") from error
            if not re.search(r"(?:^|\n)\s*(?:import\s+stripe|from\s+stripe\s+import\b)", source):
                continue
            stripe_seen = True
            for match in self._POST_WEBHOOK.finditer(source):
                supported_webhook_seen = True
                body = match.group("body")
                if self._VERIFY.search(body):
                    continue
                line = source.count("\n", 0, match.start()) + 1
                location = Location(path=relative, start_line=line)
                evidence = {
                    "artifact": "fastapi_stripe_webhook",
                    "webhook_signature_verification": "not_detected_in_handler",
                    "verification_form": "stripe_Webhook_construct_event",
                }
                findings.append(
                    Finding(
                        rule_id=self.control_id,
                        rule_version=self.control_version,
                        title="Stripe webhook handler lacks direct signature verification evidence",
                        message=(
                            "A supported FastAPI Stripe webhook handler was detected without a direct "
                            "stripe.Webhook.construct_event(...) call in the same handler body."
                        ),
                        remediation=(
                            "Verify the Stripe-Signature header against the raw request body and the reviewed "
                            "webhook signing secret before accepting the event."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        fingerprint=fingerprint_for(self.control_id, location, evidence),
                        location=location,
                        evidence=evidence,
                    )
                )

        if not stripe_seen:
            return _not_applicable(self, started_at, "No direct Stripe Python import was detected.")
        if not supported_webhook_seen:
            return _not_applicable(
                self,
                started_at,
                "No supported literal FastAPI POST webhook handler was detected for Stripe.",
            )
        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Checked bounded FastAPI Stripe webhook signature-verification evidence.",
            ),
            findings=tuple(findings),
        )


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


def _database_imports(tree: ast.Module) -> frozenset[str]:
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"sqlalchemy", "psycopg", "psycopg2"}:
                    imported.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "sqlalchemy":
                for alias in node.names:
                    if alias.name == "create_engine":
                        imported.add(alias.asname or alias.name)
            elif node.module in {"psycopg", "psycopg2"}:
                imported.add(node.module)
    return frozenset(imported)


def _database_call_client(node: ast.Call, imported: frozenset[str]) -> str | None:
    if isinstance(node.func, ast.Name) and node.func.id in imported and node.func.id == "create_engine":
        return "sqlalchemy"
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        owner = node.func.value.id
        if owner in imported and node.func.attr == "create_engine":
            return "sqlalchemy"
        if owner in imported and owner in {"psycopg", "psycopg2"} and node.func.attr == "connect":
            return owner
    return None


def _disabled_database_tls(node: ast.Call) -> str | None:
    for keyword in node.keywords:
        if keyword.arg in {"sslmode", "ssl_mode"} and isinstance(keyword.value, ast.Constant):
            value = keyword.value.value
            if isinstance(value, str) and value.lower() in {"disable", "disabled", "off", "false"}:
                return "literal_keyword"
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        dsn = node.args[0].value.lower()
        if "sslmode=disable" in dsn or "ssl_mode=disable" in dsn:
            return "literal_dsn"
    return None
