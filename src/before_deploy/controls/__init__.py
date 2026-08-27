"""Deterministic native controls and future external scanner adapters."""

from before_deploy.controls.base import Control, ControlContext, ControlResult
from before_deploy.controls.dependencies import DependencyLockfileControl
from before_deploy.controls.deployment_config import (
    CredentialedWildcardCorsControl,
    ProductionDebugControl,
)
from before_deploy.controls.fastapi_routes import FastApiRouteAuthenticationControl
from before_deploy.controls.github_actions import GitHubActionsSecurityControl
from before_deploy.controls.go import GoModuleIntegrityControl, GoTLSVerificationControl
from before_deploy.controls.go_vulnerabilities import GoVulnerabilitySnapshotControl
from before_deploy.controls.injection import SqlInjectionControl, SqlInjectionSingleLocalAliasControl
from before_deploy.controls.nextjs import (
    NextInlineServerActionLocalGuardControl,
    NextPublicEnvironmentControl,
    NextServerActionLocalGuardControl,
    NextSessionCookieControl,
    NextStaticCorsControl,
)
from before_deploy.controls.sbom import CycloneDxSbomControl
from before_deploy.controls.secrets import SecretDetectionControl


def native_controls() -> tuple[Control, ...]:
    """Return the native adapters in a stable deterministic execution order."""
    return (
        SecretDetectionControl(),
        SqlInjectionControl(),
        SqlInjectionSingleLocalAliasControl(),
        FastApiRouteAuthenticationControl(),
        ProductionDebugControl(),
        CredentialedWildcardCorsControl(),
        NextPublicEnvironmentControl(),
        NextSessionCookieControl(),
        NextStaticCorsControl(),
        NextServerActionLocalGuardControl(),
        NextInlineServerActionLocalGuardControl(),
        GitHubActionsSecurityControl(),
        DependencyLockfileControl(),
        GoModuleIntegrityControl(),
        GoTLSVerificationControl(),
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
    "GoModuleIntegrityControl",
    "GoTLSVerificationControl",
    "GoVulnerabilitySnapshotControl",
    "NextInlineServerActionLocalGuardControl",
    "NextPublicEnvironmentControl",
    "NextServerActionLocalGuardControl",
    "NextSessionCookieControl",
    "NextStaticCorsControl",
    "ProductionDebugControl",
    "SecretDetectionControl",
    "SqlInjectionControl",
    "SqlInjectionSingleLocalAliasControl",
    "native_controls",
]
