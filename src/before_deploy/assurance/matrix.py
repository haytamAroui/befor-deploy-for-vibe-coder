"""Deterministic Domain x Technology x ControlContract assurance matrix."""

from __future__ import annotations

from dataclasses import dataclass

from before_deploy.capabilities import CapabilityDefinition, CapabilityRegistry
from before_deploy.domains import SecurityDomainCatalog

MATRIX_VERSION = "0.1.0"
GLOBAL_TECHNOLOGY = "GLOBAL"


@dataclass(frozen=True)
class AssuranceMatrixContract:
    """One reviewed contract projected into an assurance-matrix cell."""

    control_id: str
    control_version: str
    capability_id: str
    implementation_id: str
    kind: str
    detection_scope: str
    exclusions: tuple[str, ...]


@dataclass(frozen=True)
class AssuranceMatrixCell:
    """All reviewed contracts for one domain/technology intersection."""

    domain_id: str
    domain_title: str
    technology: str
    contracts: tuple[AssuranceMatrixContract, ...]

    @property
    def contract_count(self) -> int:
        return len(self.contracts)

    @property
    def native_count(self) -> int:
        return sum(contract.kind == "CONTROL" for contract in self.contracts)

    @property
    def adapter_count(self) -> int:
        return sum(contract.kind == "ADAPTER" for contract in self.contracts)


@dataclass(frozen=True)
class AssuranceMatrix:
    """Versioned read-only projection of the capability and domain catalogs."""

    matrix_version: str
    capability_catalog_version: str
    capability_catalog_digest: str
    security_domain_catalog_version: str
    security_domain_catalog_digest: str
    technologies: tuple[str, ...]
    cells: tuple[AssuranceMatrixCell, ...]

    def cell(self, domain_id: str, technology: str) -> AssuranceMatrixCell | None:
        matches = [
            cell
            for cell in self.cells
            if cell.domain_id == domain_id and cell.technology == technology
        ]
        if len(matches) > 1:
            raise ValueError(
                f"Multiple assurance-matrix cells exist for {domain_id}/{technology}"
            )
        return matches[0] if matches else None


def build_assurance_matrix(
    registry: CapabilityRegistry,
    security_domain_catalog: SecurityDomainCatalog,
) -> AssuranceMatrix:
    """Build a diagnostic matrix without changing planning or release policy.

    Technology assignment is derived only from reviewed capability metadata:

    * framework predicates are projected as ``framework:<name>``;
    * otherwise language predicates are projected as ``language:<name>``;
    * capabilities with neither are projected as ``GLOBAL``.

    A framework-scoped capability is not duplicated into its language column.
    """
    buckets: dict[tuple[str, str], list[AssuranceMatrixContract]] = {}
    technologies: set[str] = {GLOBAL_TECHNOLOGY}

    for control in sorted(
        security_domain_catalog.controls.values(),
        key=lambda item: item.control_id,
    ):
        capability = registry.capabilities.get(control.capability_id)
        if capability is None:
            raise ValueError(
                f"Control contract references unknown capability: {control.control_id}"
            )
        if capability.implementation_id != control.implementation_id:
            raise ValueError(
                f"Control contract implementation mismatch: {control.control_id}"
            )

        technology_keys = _technology_keys(capability)
        technologies.update(technology_keys)
        projected = AssuranceMatrixContract(
            control_id=control.control_id,
            control_version=control.version,
            capability_id=control.capability_id,
            implementation_id=control.implementation_id,
            kind=capability.kind,
            detection_scope=control.detection_scope,
            exclusions=control.exclusions,
        )

        for domain_id in control.security_domain_ids:
            if domain_id not in security_domain_catalog.domains:
                raise ValueError(
                    f"Control contract references unknown security domain: {control.control_id}"
                )
            for technology in technology_keys:
                buckets.setdefault((domain_id, technology), []).append(projected)

    cells = tuple(
        AssuranceMatrixCell(
            domain_id=domain_id,
            domain_title=security_domain_catalog.domains[domain_id].title,
            technology=technology,
            contracts=tuple(
                sorted(
                    contracts,
                    key=lambda item: (item.kind, item.control_id),
                )
            ),
        )
        for (domain_id, technology), contracts in sorted(buckets.items())
    )

    return AssuranceMatrix(
        matrix_version=MATRIX_VERSION,
        capability_catalog_version=registry.catalog_version,
        capability_catalog_digest=registry.catalog_digest,
        security_domain_catalog_version=security_domain_catalog.catalog_version,
        security_domain_catalog_digest=security_domain_catalog.catalog_digest,
        technologies=tuple(sorted(technologies, key=_technology_sort_key)),
        cells=cells,
    )


def render_assurance_matrix_markdown(matrix: AssuranceMatrix) -> str:
    """Render a compact review artifact from the deterministic matrix."""
    domain_ids = tuple(sorted({cell.domain_id for cell in matrix.cells}))
    cell_index = {
        (cell.domain_id, cell.technology): cell
        for cell in matrix.cells
    }

    lines = [
        "# Domain Assurance Matrix",
        "",
        f"- Matrix version: `{matrix.matrix_version}`",
        f"- Capability catalog: `{matrix.capability_catalog_version}`",
        f"- Security-domain catalog: `{matrix.security_domain_catalog_version}`",
        "",
        "This artifact is diagnostic. Contract counts do not establish security, "
        "compliance, or release approval.",
        "",
        "| Domain | " + " | ".join(matrix.technologies) + " |",
        "|---|" + "|".join("---:" for _ in matrix.technologies) + "|",
    ]

    for domain_id in domain_ids:
        title = next(
            cell.domain_title for cell in matrix.cells if cell.domain_id == domain_id
        )
        counts = []
        for technology in matrix.technologies:
            cell = cell_index.get((domain_id, technology))
            counts.append(str(cell.contract_count) if cell else "0")
        lines.append(
            f"| `{domain_id}` {title} | " + " | ".join(counts) + " |"
        )

    lines.extend(["", "## Contract detail", ""])
    for cell in matrix.cells:
        lines.append(
            f"### `{cell.domain_id}` × `{cell.technology}` "
            f"({cell.contract_count} contract{'s' if cell.contract_count != 1 else ''})"
        )
        lines.append("")
        for contract in cell.contracts:
            lines.append(
                f"- `{contract.control_id}` — `{contract.kind}` — "
                f"`{contract.implementation_id}`"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _technology_keys(capability: CapabilityDefinition) -> tuple[str, ...]:
    if capability.frameworks:
        return tuple(f"framework:{value}" for value in sorted(capability.frameworks))
    if capability.languages:
        return tuple(f"language:{value}" for value in sorted(capability.languages))
    return (GLOBAL_TECHNOLOGY,)


def _technology_sort_key(value: str) -> tuple[int, str]:
    if value == GLOBAL_TECHNOLOGY:
        return (0, value)
    if value.startswith("language:"):
        return (1, value)
    return (2, value)
