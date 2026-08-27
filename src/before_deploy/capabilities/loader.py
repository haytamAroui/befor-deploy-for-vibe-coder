"""Strict loading and semantic hashing for non-executable capability manifests."""

from __future__ import annotations

from hashlib import sha256
from json import dumps
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from before_deploy.capabilities.schema import (
    CapabilityDefinition,
    CapabilityRegistry,
    validate_kind,
)

CATALOG_FILE_NAME = "catalog.yaml"
CATALOG_SCHEMA_VERSION = 1
_FORBIDDEN_TEXT_FRAGMENTS = ("http://", "https://", "file://", "`", "$(")
_FORBIDDEN_COMMAND_PREFIXES = ("bash -", "curl ", "pwsh -", "python -", "python3 ", "sh -", "wget ")

APPROVED_IMPLEMENTATION_IDS = frozenset(
    {
        "SEC-API-001",
        "SEC-CICD-001",
        "SEC-CONFIG-001",
        "SEC-CONFIG-002",
        "SEC-DEP-001",
        "SEC-DEP-VULN-001",
        "SEC-GO-MODULE-001",
        "SEC-GO-TLS-001",
        "SEC-GO-VULN-001",
        "SEC-GOSEC-001",
        "SEC-NEXT-COOKIE-001",
        "SEC-NEXT-CORS-001",
        "SEC-NEXT-ACTION-001",
        "SEC-NEXT-INLINE-ACTION-001",
        "SEC-NEXT-ENV-001",
        "SEC-PHP-LARAVEL-COMPOSER-LOCK-001",
        "SEC-PROVENANCE-001",
        "SEC-RELEASE-001",
        "SEC-RUST-CARGO-LOCK-001",
        "SEC-SAST-001",
        "SEC-SAST-SQL-ALIAS-001",
        "SEC-SAST-SEMGREP-001",
        "SEC-SECRET-001",
        "SEC-SECRET-GITLEAKS-001",
        "SEC-TRIVY-CONFIG-001",
    }
)


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys instead of silently replacing them."""


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
    """Return the packaged source directory containing the trusted built-in YAML manifests."""
    return Path(__file__).with_name("manifests")


def load_builtin_capability_registry() -> CapabilityRegistry:
    """Load the packaged reviewed catalog; no repository-supplied registry is discovered automatically."""
    return load_capability_registry(builtin_manifest_directory())


def load_capability_registry(directory: Path) -> CapabilityRegistry:
    """Load a strictly validated registry directory and return its canonical semantic digest."""
    if not directory.is_dir():
        raise ValueError(f"Capability manifest directory is not a directory: {directory}")
    catalog_path = directory / CATALOG_FILE_NAME
    catalog = _load_mapping(catalog_path, "capability catalog")
    _reject_unknown_keys(catalog, {"schema_version", "catalog_version", "manifests"}, catalog_path)
    if catalog.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise ValueError(f"Capability catalog schema_version must be {CATALOG_SCHEMA_VERSION}")
    catalog_version = _required_string(catalog, "catalog_version", catalog_path)
    manifest_names = _string_tuple(catalog.get("manifests"), "manifests", catalog_path, allow_empty=False)
    if len(set(manifest_names)) != len(manifest_names):
        raise ValueError("Capability catalog manifests must not contain duplicate entries")

    capabilities: dict[str, CapabilityDefinition] = {}
    implementation_ids: set[str] = set()
    for name in manifest_names:
        if Path(name).name != name or not name.endswith(".yaml"):
            raise ValueError(f"Capability manifest name must be a local .yaml filename: {name}")
        definition = _parse_definition(directory / name)
        if definition.capability_id in capabilities:
            raise ValueError(f"Duplicate capability ID: {definition.capability_id}")
        if definition.implementation_id in implementation_ids:
            raise ValueError(
                f"Multiple capability manifests reference implementation: {definition.implementation_id}"
            )
        capabilities[definition.capability_id] = definition
        implementation_ids.add(definition.implementation_id)

    return CapabilityRegistry(
        schema_version=CATALOG_SCHEMA_VERSION,
        catalog_version=catalog_version,
        catalog_digest=_semantic_digest(catalog_version, capabilities.values()),
        capabilities=MappingProxyType(dict(sorted(capabilities.items()))),
    )


def _parse_definition(path: Path) -> CapabilityDefinition:
    raw = _load_mapping(path, "capability manifest")
    _reject_unknown_keys(
        raw,
        {
            "schema_version",
            "id",
            "version",
            "implementation_id",
            "kind",
            "title",
            "applies_when",
            "security_domains",
            "exclusions",
        },
        path,
    )
    if raw.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise ValueError(f"Capability {path.name} schema_version must be {CATALOG_SCHEMA_VERSION}")
    capability_id = _required_string(raw, "id", path)
    implementation_id = _required_string(raw, "implementation_id", path)
    if implementation_id not in APPROVED_IMPLEMENTATION_IDS:
        raise ValueError(f"Capability {capability_id} references unapproved implementation: {implementation_id}")
    applies_when = raw.get("applies_when")
    if not isinstance(applies_when, dict):
        raise ValueError(f"Capability {capability_id} applies_when must be a mapping")
    _reject_unknown_keys(
        applies_when,
        {"languages", "frameworks", "requires_github_workflow", "required_project_signals"},
        path,
    )
    requires_workflow = applies_when.get("requires_github_workflow", False)
    if not isinstance(requires_workflow, bool):
        raise ValueError(f"Capability {capability_id} requires_github_workflow must be boolean")
    return CapabilityDefinition(
        capability_id=capability_id,
        version=_required_string(raw, "version", path),
        implementation_id=implementation_id,
        kind=validate_kind(_required_string(raw, "kind", path)),
        title=_required_string(raw, "title", path),
        languages=frozenset(_string_tuple(applies_when.get("languages", []), "languages", path)),
        frameworks=frozenset(_string_tuple(applies_when.get("frameworks", []), "frameworks", path)),
        requires_github_workflow=requires_workflow,
        required_project_signals=frozenset(
            _string_tuple(
                applies_when.get("required_project_signals", []),
                "required_project_signals",
                path,
            )
        ),
        security_domains=_string_tuple(raw.get("security_domains"), "security_domains", path),
        exclusions=_string_tuple(raw.get("exclusions"), "exclusions", path),
        source_path=path,
    )


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


def _semantic_digest(catalog_version: str, definitions: object) -> str:
    canonical = {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "catalog_version": catalog_version,
        "capabilities": [
            {
                "id": definition.capability_id,
                "version": definition.version,
                "implementation_id": definition.implementation_id,
                "kind": definition.kind,
                "title": definition.title,
                "languages": sorted(definition.languages),
                "frameworks": sorted(definition.frameworks),
                "requires_github_workflow": definition.requires_github_workflow,
                "required_project_signals": sorted(definition.required_project_signals),
                "security_domains": list(definition.security_domains),
                "exclusions": list(definition.exclusions),
            }
            for definition in sorted(definitions, key=lambda item: item.capability_id)
        ],
    }
    encoded = dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(encoded).hexdigest()
