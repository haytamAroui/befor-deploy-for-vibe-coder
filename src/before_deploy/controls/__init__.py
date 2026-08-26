"""Deterministic native controls and future external scanner adapters."""

from before_deploy.controls.base import Control, ControlContext, ControlResult
from before_deploy.controls.dependencies import DependencyLockfileControl
from before_deploy.controls.deployment_config import (
    CredentialedWildcardCorsControl,
    ProductionDebugControl,
)
from before_deploy.controls.fastapi_routes import FastApiRouteAuthenticationControl
from before_deploy.controls.github_actions import GitHubActionsSecurityControl
from before_deploy.controls.injection import SqlInjectionControl
from before_deploy.controls.sbom import CycloneDxSbomControl
from before_deploy.controls.secrets import SecretDetectionControl


def native_controls() -> tuple[Control, ...]:
    """Return the native adapters in a stable deterministic execution order."""
    return (
        SecretDetectionControl(),
        SqlInjectionControl(),
        FastApiRouteAuthenticationControl(),
        ProductionDebugControl(),
        CredentialedWildcardCorsControl(),
        GitHubActionsSecurityControl(),
        DependencyLockfileControl(),
        CycloneDxSbomControl(),
    )


__all__ = [
    "Control",
    "ControlContext",
    "ControlResult",
    "CredentialedWildcardCorsControl",
    "CycloneDxSbomControl",
    "DependencyLockfileControl",
    "FastApiRouteAuthenticationControl",
    "GitHubActionsSecurityControl",
    "ProductionDebugControl",
    "SecretDetectionControl",
    "SqlInjectionControl",
    "native_controls",
]
