"""Bounded Docker Compose privileged-service evidence without Docker or Compose execution."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode

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


_COMPOSE_FILENAMES = frozenset(
    {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
)
_EXCLUDED_DYNAMIC_SYNTAX = re.compile(r"\$\{|\{\{")
_EXCLUDED_YAML_REUSE = re.compile(r"(?:&|\*)[A-Za-z_][A-Za-z0-9_-]*|<<:")
_BOOLEAN_TAG = "tag:yaml.org,2002:bool"


class DockerComposePrivilegedControl:
    """Report direct literal privileged services in conventional root Compose files only."""

    control_id = "SEC-COMPOSE-PRIVILEGED-001"
    control_version = "0.1.0"

    def run(self, context: ControlContext) -> ControlResult:
        started_at = utc_now()
        compose_files = _root_compose_files(context.repository_root, context.inventory.files)
        if not compose_files:
            return _not_applicable(self, started_at, "No supported root Docker Compose file was detected.")

        findings: list[Finding] = []
        for relative_path, compose_path in compose_files:
            try:
                source = compose_path.read_text(encoding="utf-8")
            except OSError:
                return _error_result(self, started_at, "COMPOSE_YAML_UNREADABLE")
            except UnicodeDecodeError:
                return _error_result(self, started_at, "COMPOSE_YAML_INVALID_ENCODING")
            if _EXCLUDED_DYNAMIC_SYNTAX.search(source) or _EXCLUDED_YAML_REUSE.search(source):
                continue
            try:
                documents = tuple(yaml.compose_all(source, Loader=yaml.SafeLoader))
            except yaml.YAMLError:
                return _error_result(self, started_at, "COMPOSE_YAML_INVALID")
            if len(documents) != 1 or not isinstance(documents[0], MappingNode):
                continue
            document = documents[0]
            if _mapping_value(document, "include") is not None or _has_yaml_reuse(document):
                continue
            findings.extend(_privileged_findings(self, relative_path, document))

        return ControlResult(
            execution=ControlExecution(
                control_id=self.control_id,
                control_version=self.control_version,
                status=ExecutionStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
                message="Inspected supported root Docker Compose files for direct literal privileged services.",
            ),
            findings=tuple(sorted(findings, key=lambda finding: (finding.location.path, finding.location.start_line))),
        )


def _root_compose_files(repository_root: Path, files: tuple[Path, ...]) -> tuple[tuple[str, Path], ...]:
    root_files = []
    for path in files:
        relative_path = path.relative_to(repository_root).as_posix()
        if "/" not in relative_path and relative_path in _COMPOSE_FILENAMES:
            root_files.append((relative_path, path))
    return tuple(sorted(root_files))


def _privileged_findings(
    control: DockerComposePrivilegedControl, relative_path: str, document: MappingNode
) -> tuple[Finding, ...]:
    services = _mapping_value(document, "services")
    if not isinstance(services, MappingNode):
        return ()
    findings: list[Finding] = []
    for service_name, service in services.value:
        if not isinstance(service_name, ScalarNode) or not isinstance(service, MappingNode):
            continue
        if _mapping_value(service, "extends") is not None or _mapping_value(service, "profiles") is not None:
            continue
        privileged = _mapping_value(service, "privileged")
        if not _is_direct_true(privileged):
            continue
        location = Location(path=relative_path, start_line=privileged.start_mark.line + 1)
        evidence = {"artifact": "compose", "issue": "privileged_service"}
        findings.append(
            Finding(
                rule_id=control.control_id,
                rule_version=control.control_version,
                title="Docker Compose service enables privileged mode",
                message=(
                    "A supported direct Docker Compose service sets a literal privileged value to true. "
                    "Review whether elevated container privileges are required."
                ),
                remediation=(
                    "Remove the literal privileged setting where possible, or document and review the "
                    "minimum required container privileges."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                fingerprint=fingerprint_for(control.control_id, location, evidence),
                location=location,
                evidence=evidence,
            )
        )
    return tuple(findings)


def _mapping_value(mapping: MappingNode, name: str) -> Node | None:
    for key, value in mapping.value:
        if isinstance(key, ScalarNode) and key.value == name:
            return value
    return None


def _is_direct_true(node: Node | None) -> bool:
    return isinstance(node, ScalarNode) and node.tag == _BOOLEAN_TAG and node.value == "true"


def _has_yaml_reuse(node: Node) -> bool:
    if getattr(node, "anchor", None) is not None:
        return True
    if isinstance(node, MappingNode):
        return any(
            (isinstance(key, ScalarNode) and key.value == "<<") or _has_yaml_reuse(key) or _has_yaml_reuse(value)
            for key, value in node.value
        )
    if isinstance(node, yaml.nodes.SequenceNode):
        return any(_has_yaml_reuse(item) for item in node.value)
    return False


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
            message=f"Docker Compose control error: {error_kind}",
            metadata={"error_kind": error_kind},
        )
    )
