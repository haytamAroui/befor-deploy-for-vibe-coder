"""Render the packaged Domain x Technology x ControlContract matrix."""

from __future__ import annotations

import argparse
from pathlib import Path

from before_deploy.assurance import (
    build_assurance_matrix,
    render_assurance_matrix_markdown,
)
from before_deploy.capabilities import load_builtin_capability_registry
from before_deploy.domains import load_builtin_security_domain_catalog


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/domain-assurance-matrix.md"),
    )
    args = parser.parse_args()

    matrix = build_assurance_matrix(
        load_builtin_capability_registry(),
        load_builtin_security_domain_catalog(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_assurance_matrix_markdown(matrix), encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
