"""Strict loading and semantic hashing for the non-executable security-domain catalog."""

from __future__ import annotations

from hashlib import sha256
from json import dumps
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from before_deploy.capabilities import CapabilityRegistry, load_builtin_capability_registry
from before_deploy.domains.schema import (
    ControlDefinition,
    DomainApplicability,
    SecurityDomainCatalog,
    SecurityDomainDefinition,
    validate_category,
)

CATALOG_FILE_NAME = "catalog.yaml"
CATALOG_SCHEMA_VERSION = 1
_APPROVED_REFERENCE_URLS = frozenset(
    {
        "https://www.nist.gov/news-events/news/2025/12/secure-software-development-framework-ssdf-version-12-available-public",
        "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
        "https://slsa.dev/spec/v1.2/tracks",
    }
)
_FORBIDDEN_TEXT_FRAGMENTS = ("http://", "https://", "file://", "`", "$(")
_FORBIDDEN_COMMAND_PREFIXES = ("bash -", "curl ", "pwsh -", "python -", "python3 ", "sh -", "wget ")


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that fails on duplicate mapping keys."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"Duplicate YAML mapping key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def builtin_manifest_directory() -> Path:
    """Return the packaged source directory containing reviewed catalog metadata."""
    return Path(__file__).with_name("manifests")


def load_builtin_security_domain_catalog() -> SecurityDomainCatalog:
    """Load only packaged reviewed metadata; never discover catalog files in a target repository."""
    return load_security_domain_catalog(
        builtin_manifest_directory(), capability_registry=load_builtin_capability_registry()
    )


def load_security_domain_catalog(
    directory: Path, *, capability_registry: CapabilityRegistry
) -> SecurityDomainCatalog:
    """Load and validate a local catalog directory with no executable configuration surface."""
    if not directory.is_dir():
        raise ValueError(f"Security domain catalog directory is not a directory: {directory}")
    catalog_path = directory / CATALOG_FILE_NAME
    catalog = _load_mapping(catalog_path, "security domain catalog")
    _reject_unknown_keys(
        catalog,
        {"schema_version", "catalog_version", "references", "domain_manifests", "control_manifests"},
        catalog_path,
    )
    if catalog.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise ValueError(f"Security domain catalog schema_version must be {CATALOG_SCHEMA_VERSION}")
    catalog_version = _required_string(catalog, "catalog_version", catalog_path)
    references = _parse_references(catalog.get("references"), catalog_path)
    domain_names = _manifest_names(catalog.get("domain_manifests"), "domain_manifests", catalog_path)
    control_names = _manifest_names(catalog.get("control_manifests"), "control_manifests", catalog_path)
    if set(domain_names).intersection(control_names):
        raise ValueError("Domain and control manifests must be distinct files")

    domains: dict[str, SecurityDomainDefinition] = {}
    for name in domain_names:
        for definition in _parse_domain_bundle(directory / name, references):
            if definition.domain_id in domains:
                raise ValueError(f"Duplicate security domain ID: {definition.domain_id}")
            domains[definition.domain_id] = definition

    controls: dict[str, ControlDefinition] = {}
    capability_ids: set[str] = set()
    implementation_ids: set[str] = set()
    for name in control_names:
        for definition in _parse_control_bundle(directory / name, references):
            if definition.control_id in controls:
                raise ValueError(f"Duplicate control catalog ID: {definition.control_id}")
            if definition.capability_id in capability_ids:
                raise ValueError(f"Multiple control contracts reference capability: {definition.capability_id}")
            if definition.implementation_id in implementation_ids:
                raise ValueError(
                    f"Multiple control contracts reference implementation: {definition.implementation_id}"
                )
            capability = capability_registry.capabilities.get(definition.capability_id)
            if capability is None:
                raise ValueError(
                    f"Control {definition.control_id} references unknown capability: {definition.capability_id}"
                )
            if capability.implementation_id != definition.implementation_id:
                raise ValueError(
                    f"Control {definition.control_id} implementation does not match capability: "
                    f"{definition.capability_id}"
                )
            unknown_domains = sorted(set(definition.security_domain_ids) - set(domains))
            if unknown_domains:
                raise ValueError(
                    f"Control {definition.control_id} references unknown security domains: "
                    f"{', '.join(unknown_domains)}"
                )
            controls[definition.control_id] = definition
            capability_ids.add(definition.capability_id)
            implementation_ids.add(definition.implementation_id)

    return SecurityDomainCatalog(
        schema_version=CATALOG_SCHEMA_VERSION,
        catalog_version=catalog_version,
        catalog_digest=_semantic_digest(catalog_version, references, domains.values(), controls.values()),
        domains=MappingProxyType(dict(sorted(domains.items()))),
        controls=MappingProxyType(dict(sorted(controls.items()))),
    )


def _parse_references(value: object, path: Path) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{path.name} references must be a non-empty mapping")
    references: dict[str, dict[str, str]] = {}
    for reference_id, raw in value.items():
        if not isinstance(reference_id, str) or not reference_id.strip():
            raise ValueError(f"{path.name} reference IDs must be non-empty strings")
        if not isinstance(raw, dict):
            raise ValueError(f"{path.name} reference {reference_id} must be a mapping")
        _reject_unknown_keys(raw, {"title", "url"}, path)
        title = _required_string(raw, "title", path)
        url = raw.get("url")
        if not isinstance(url, str) or url not in _APPROVED_REFERENCE_URLS:
            raise ValueError(f"{path.name} reference {reference_id} URL is not approved")
        references[_safe_text(reference_id.strip(), "reference ID", path)] = {"title": title, "url": url}
    return dict(sorted(references.items()))


def _manifest_names(value: object, field: str, path: Path) -> tuple[str, ...]:
    names = _string_tuple(value, field, path, allow_empty=False)
    for name in names:
        if Path(name).name != name or not name.endswith(".yaml"):
            raise ValueError(f"Security domain catalog manifest name must be a local .yaml filename: {name}")
    return names


def _parse_domain_bundle(
    path: Path, references: dict[str, dict[str, str]]
) -> tuple[SecurityDomainDefinition, ...]:
    bundle = _load_mapping(path, "security domain manifest bundle")
    _reject_unknown_keys(bundle, {"schema_version", "domains"}, path)
    if bundle.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise ValueError(f"Security domain bundle {path.name} schema_version must be {CATALOG_SCHEMA_VERSION}")
    raw_domains = bundle.get("domains")
    if not isinstance(raw_domains, list) or not raw_domains:
        raise ValueError(f"Security domain bundle {path.name} domains must be a non-empty list")
    if not all(isinstance(raw, dict) for raw in raw_domains):
        raise ValueError(f"Security domain bundle {path.name} domains must contain mappings")
    return tuple(_parse_domain(raw, path, references) for raw in raw_domains)


def _parse_domain(
    raw: dict[str, Any], path: Path, references: dict[str, dict[str, str]]
) -> SecurityDomainDefinition:
    _reject_unknown_keys(
        raw,
        {"id", "version", "title", "category", "description", "applies_when", "references", "exclusions"},
        path,
    )
    domain_id = _required_string(raw, "id", path)
    if not domain_id.startswith("DOMAIN-"):
        raise ValueError(f"Security domain ID must start with DOMAIN-: {domain_id}")
    return SecurityDomainDefinition(
        domain_id=domain_id,
        version=_required_string(raw, "version", path),
        title=_required_string(raw, "title", path),
        category=validate_category(_required_string(raw, "category", path)),
        description=_required_string(raw, "description", path),
        applies_when=_parse_domain_applicability(raw.get("applies_when"), path),
        reference_ids=_reference_ids(raw.get("references"), references, path),
        exclusions=_string_tuple(raw.get("exclusions"), "exclusions", path),
        source_path=path,
    )


def _parse_control_bundle(
    path: Path, references: dict[str, dict[str, str]]
) -> tuple[ControlDefinition, ...]:
    bundle = _load_mapping(path, "control catalog manifest bundle")
    _reject_unknown_keys(bundle, {"schema_version", "controls"}, path)
    if bundle.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise ValueError(f"Control catalog bundle {path.name} schema_version must be {CATALOG_SCHEMA_VERSION}")
    raw_controls = bundle.get("controls")
    if not isinstance(raw_controls, list) or not raw_controls:
        raise ValueError(f"Control catalog bundle {path.name} controls must be a non-empty list")
    if not all(isinstance(raw, dict) for raw in raw_controls):
        raise ValueError(f"Control catalog bundle {path.name} controls must contain mappings")
    return tuple(_parse_control(raw, path, references) for raw in raw_controls)


def _parse_control(
    raw: dict[str, Any], path: Path, references: dict[str, dict[str, str]]
) -> ControlDefinition:
    _reject_unknown_keys(
        raw,
        {"id", "version", "title", "capability_id", "implementation_id", "security_domains", "detection_scope", "exclusions", "references"},
        path,
    )
    control_id = _required_string(raw, "id", path)
    if not control_id.startswith("CONTROL-"):
        raise ValueError(f"Control catalog ID must start with CONTROL-: {control_id}")
    return ControlDefinition(
        control_id=control_id,
        version=_required_string(raw, "version", path),
        title=_required_string(raw, "title", path),
        capability_id=_required_string(raw, "capability_id", path),
        implementation_id=_required_string(raw, "implementation_id", path),
        security_domain_ids=_string_tuple(raw.get("security_domains"), "security_domains", path, allow_empty=False),
        detection_scope=_required_string(raw, "detection_scope", path),
        exclusions=_string_tuple(raw.get("exclusions"), "exclusions", path),
        reference_ids=_reference_ids(raw.get("references"), references, path),
        source_path=path,
    )


def _parse_domain_applicability(value: object, path: Path) -> DomainApplicability:
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} applies_when must be a mapping")
    _reject_unknown_keys(
        value,
        {"repository_wide", "languages", "frameworks", "package_managers", "evidence_signal_ids"},
        path,
    )
    repository_wide = value.get("repository_wide", False)
    if not isinstance(repository_wide, bool):
        raise ValueError(f"{path.name} repository_wide must be boolean")
    return DomainApplicability(
        repository_wide=repository_wide,
        languages=frozenset(_string_tuple(value.get("languages", []), "languages", path)),
        frameworks=frozenset(_string_tuple(value.get("frameworks", []), "frameworks", path)),
        package_managers=frozenset(
            _string_tuple(value.get("package_managers", []), "package_managers", path)
        ),
        evidence_signal_ids=frozenset(
            _string_tuple(value.get("evidence_signal_ids", []), "evidence_signal_ids", path)
        ),
    )


def _reference_ids(value: object, references: dict[str, dict[str, str]], path: Path) -> tuple[str, ...]:
    ids = _string_tuple(value, "references", path)
    unknown = sorted(set(ids) - set(references))
    if unknown:
        raise ValueError(f"{path.name} references unknown standard IDs: {', '.join(unknown)}")
    return ids


def _load_mapping(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError, ValueError) as error:
        raise ValueError(f"Unable to load {label}: {path}") from error
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{label.capitalize()} must be a mapping with string keys: {path}")
    return raw


def _reject_unknown_keys(raw: dict[str, Any], allowed: set[str], path: Path) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"Unsupported fields in {path.name}: {', '.join(unknown)}")


def _required_string(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path.name} requires non-empty string field: {key}")
    return _safe_text(value.strip(), key, path)


def _string_tuple(value: object, field: str, path: Path, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{path.name} field {field} must be a list of non-empty strings")
    items = tuple(_safe_text(item.strip(), field, path) for item in value)
    if not allow_empty and not items:
        raise ValueError(f"{path.name} field {field} must not be empty")
    if len(set(items)) != len(items):
        raise ValueError(f"{path.name} field {field} must not contain duplicates")
    return items


def _safe_text(value: str, field: str, path: Path) -> str:
    normalized = value.lower()
    if any(fragment in normalized for fragment in _FORBIDDEN_TEXT_FRAGMENTS):
        raise ValueError(f"{path.name} field {field} contains a forbidden executable or URL marker")
    if normalized.startswith(_FORBIDDEN_COMMAND_PREFIXES):
        raise ValueError(f"{path.name} field {field} contains a forbidden command marker")
    return value


def _semantic_digest(
    catalog_version: str,
    references: dict[str, dict[str, str]],
    domains: object,
    controls: object,
) -> str:
    canonical = {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "catalog_version": catalog_version,
        "references": references,
        "domains": [
            {
                "id": definition.domain_id,
                "version": definition.version,
                "title": definition.title,
                "category": definition.category,
                "description": definition.description,
                "repository_wide": definition.applies_when.repository_wide,
                "languages": sorted(definition.applies_when.languages),
                "frameworks": sorted(definition.applies_when.frameworks),
                "package_managers": sorted(definition.applies_when.package_managers),
                "evidence_signal_ids": sorted(definition.applies_when.evidence_signal_ids),
                "references": list(definition.reference_ids),
                "exclusions": list(definition.exclusions),
            }
            for definition in sorted(domains, key=lambda item: item.domain_id)
        ],
        "controls": [
            {
                "id": definition.control_id,
                "version": definition.version,
                "title": definition.title,
                "capability_id": definition.capability_id,
                "implementation_id": definition.implementation_id,
                "security_domains": list(definition.security_domain_ids),
                "detection_scope": definition.detection_scope,
                "exclusions": list(definition.exclusions),
                "references": list(definition.reference_ids),
            }
            for definition in sorted(controls, key=lambda item: item.control_id)
        ],
    }
    encoded = dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(encoded).hexdigest()
