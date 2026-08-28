"""Deterministic native controls and future external scanner adapters."""

from before_deploy.controls.base import Control, ControlContext, ControlResult
from before_deploy.controls.dependencies import DependencyLockfileControl
from before_deploy.controls.deployment_config import (
    CredentialedWildcardCorsControl,
    ProductionDebugControl,
)
from before_deploy.controls.docker_compose import DockerComposePrivilegedControl
from before_deploy.controls.fastapi_authorization import FastApiAuthorizationDeclarationControl
from before_deploy.controls.fastapi_input import FastApiInputValidationControl
from before_deploy.controls.fastapi_upload import FastApiUploadFilenameControl
from before_deploy.controls.python_data_integrity import PythonDataIntegrityControl
from before_deploy.controls.python_sensitive_data import PythonSensitiveDataLoggingControl
from before_deploy.controls.python_error_handling import PythonErrorHandlingControl
from before_deploy.controls.python_observability import PythonObservabilityControl
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
from before_deploy.controls.php_laravel import LaravelComposerLockfileControl
from before_deploy.controls.ruby_rails import RailsGemfileLockfileControl
from before_deploy.controls.rust_cargo import RustCargoLockfileControl
from before_deploy.controls.sbom import CycloneDxSbomControl
from before_deploy.controls.secrets import SecretDetectionControl


def native_controls() -> tuple[Control, ...]:
    """Return the native adapters in a stable deterministic execution order."""
    return (
        SecretDetectionControl(),
        SqlInjectionControl(),
        SqlInjectionSingleLocalAliasControl(),
        FastApiRouteAuthenticationControl(),
        FastApiAuthorizationDeclarationControl(),
        FastApiInputValidationControl(),
        FastApiUploadFilenameControl(),
        PythonDataIntegrityControl(),
        PythonSensitiveDataLoggingControl(),
        PythonErrorHandlingControl(),
        PythonObservabilityControl(),
        ProductionDebugControl(),
        CredentialedWildcardCorsControl(),
        DockerComposePrivilegedControl(),
        NextPublicEnvironmentControl(),
        NextSessionCookieControl(),
        NextStaticCorsControl(),
        NextServerActionLocalGuardControl(),
        NextInlineServerActionLocalGuardControl(),
        GitHubActionsSecurityControl(),
        DependencyLockfileControl(),
        LaravelComposerLockfileControl(),
        RustCargoLockfileControl(),
        RailsGemfileLockfileControl(),
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
    "DockerComposePrivilegedControl",
    "FastApiAuthorizationDeclarationControl",
    "FastApiInputValidationControl",
    "FastApiUploadFilenameControl",
    "PythonDataIntegrityControl",
    "PythonSensitiveDataLoggingControl",
    "PythonErrorHandlingControl",
    "PythonObservabilityControl",
    "FastApiRouteAuthenticationControl",
    "GitHubActionsSecurityControl",
    "GoModuleIntegrityControl",
    "GoTLSVerificationControl",
    "GoVulnerabilitySnapshotControl",
    "LaravelComposerLockfileControl",
    "NextInlineServerActionLocalGuardControl",
    "NextPublicEnvironmentControl",
    "NextServerActionLocalGuardControl",
    "NextSessionCookieControl",
    "NextStaticCorsControl",
    "ProductionDebugControl",
    "RailsGemfileLockfileControl",
    "RustCargoLockfileControl",
    "SecretDetectionControl",
    "SqlInjectionControl",
    "SqlInjectionSingleLocalAliasControl",
    "native_controls",
]
