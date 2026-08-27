"""Read-only security-domain and control catalog interfaces."""

from before_deploy.domains.loader import (
    builtin_manifest_directory,
    load_builtin_security_domain_catalog,
    load_security_domain_catalog,
)
from before_deploy.domains.schema import (
    ControlDefinition,
    DomainApplicability,
    SecurityDomainCatalog,
    SecurityDomainDefinition,
)

__all__ = [
    "ControlDefinition",
    "DomainApplicability",
    "SecurityDomainCatalog",
    "SecurityDomainDefinition",
    "builtin_manifest_directory",
    "load_builtin_security_domain_catalog",
    "load_security_domain_catalog",
]
