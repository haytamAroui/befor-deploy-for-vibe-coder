"""SARIF 2.1.0-compatible report serialization."""

from __future__ import annotations

from json import dumps

from before_deploy import __version__
from before_deploy.models import Finding, ScanResult, Severity, to_primitive

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render_sarif(result: ScanResult) -> str:
    """Render a conservative SARIF subset without raw secret evidence."""
    rules = {
        finding.rule_id: {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {"text": finding.remediation},
            "properties": {
                "ruleVersion": finding.rule_version,
                "defaultSeverity": finding.severity.value,
            },
        }
        for finding in result.findings
    }
    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "before-deploy",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/haytamAroui/befor-deploy-for-vibe-coder",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "automationDetails": {"id": result.manifest.scan_id},
                "invocations": [
                    {
                        "executionSuccessful": result.decision.outcome.value != "ERROR",
                        "workingDirectory": {"uri": result.manifest.repository_path},
                    }
                ],
                "results": [_finding_to_sarif(finding) for finding in result.findings],
                "properties": {
                    "beforeDeployProjectProfile": (
                        to_primitive(result.project_profile) if result.project_profile else None
                    ),
                    "beforeDeploySecurityAnalysisPlan": (
                        to_primitive(result.security_analysis_plan)
                        if result.security_analysis_plan
                        else None
                    ),
                    "beforeDeployCoverageAudit": (
                        to_primitive(result.coverage_audit) if result.coverage_audit else None
                    ),
                    "beforeDeploySecurityDomainCatalog": (
                        {
                            "version": result.security_analysis_plan.security_domain_catalog_version,
                            "digest": result.security_analysis_plan.security_domain_catalog_digest,
                        }
                        if result.security_analysis_plan
                        and result.security_analysis_plan.security_domain_catalog_digest
                        else None
                    ),
                },
            }
        ],
    }
    return dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _finding_to_sarif(finding: Finding) -> dict:
    result = {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "partialFingerprints": {"before-deploy/v1": finding.fingerprint},
        "properties": {
            "confidence": finding.confidence.value,
            "disposition": finding.disposition.value if finding.disposition else "UNCLASSIFIED",
            "ruleVersion": finding.rule_version,
        },
    }
    if finding.location:
        physical_location = {"artifactLocation": {"uri": finding.location.path}}
        if finding.location.start_line is not None:
            physical_location["region"] = {"startLine": finding.location.start_line}
        result["locations"] = [{"physicalLocation": physical_location}]
    return result


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.BLOCKER, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"
