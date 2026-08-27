"""Read-only security-domain and control catalog interfaces."""

from before_deploy.domains.evaluator import (
    ActivationStatus,
    DomainActivation,
    evaluate_domains,
)
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
    "ActivationStatus",
    "ControlDefinition",
    "DomainActivation",
    "DomainApplicability",
    "SecurityDomainCatalog",
    "SecurityDomainDefinition",
    "builtin_manifest_directory",
    "evaluate_domains",
    "load_builtin_security_domain_catalog",
    "load_security_domain_catalog",
]
