"""
Systematic corrections for v2.0 auditor JSON.

v2.0 changes:
  - All SEC-* rule IDs are gone, replaced by categorized prefixes
  - Reference URLs in the JSON use old /docs/how-to/ paths (mostly 404)
  - This module now fixes broken URLs and applies any needed corrections

Apply once, right after parsing, before relationship-building.
"""

from typing import List
from models import Finding


# -----------------------------------------------------------------------
# URL replacement map: old broken URLs -> working replacements
# 16 of 22 URLs in the v2 JSON are 404. Map them to working alternatives.
# -----------------------------------------------------------------------
_URL_REPLACEMENTS = {
    "https://docs.cloud.f5.com/docs/how-to/advanced-security/service-policies":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/advanced-security/user-identification":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-networking/configure-http-header-processing":
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    "https://docs.cloud.f5.com/docs/how-to/app-networking/dns":
        "https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
    "https://docs.cloud.f5.com/docs/how-to/app-security/api-discovery":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/api-protection":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/bot-defense":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/cfg-waf":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/client-side-defense":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/configure-waf-exclusion-rules":
        "https://docs.cloud.f5.com/docs-v2/platform/reference/attack-signatures",
    "https://docs.cloud.f5.com/docs/how-to/app-security/ddos-mitigation":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/global-log-receiver":
        "https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
    "https://docs.cloud.f5.com/docs/how-to/app-security/malicious-users":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/app-security/manage-certificates":
        "https://docs.cloud.f5.com/docs-v2/administration/how-tos/user-mgmt/general-management",
    "https://docs.cloud.f5.com/docs/how-to/app-security/rate-limiting":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    "https://docs.cloud.f5.com/docs/how-to/monitoring/alerting":
        "https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
    # Old v1 URLs that may still appear
    "https://docs.cloud.f5.com/docs/how-to/app-security/waf-policy":
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
}


def _fix_reference_urls(finding: Finding) -> None:
    """Replace known broken reference URLs with working alternatives."""
    if finding.reference_url in _URL_REPLACEMENTS:
        finding.reference_url = _URL_REPLACEMENTS[finding.reference_url]


def _annotate_service_policy_count(finding: Finding) -> None:
    """AC-01: Append the count of assigned service policies to the message."""
    if finding.rule_id != "AC-01":
        return
    cv = finding.current_value
    if isinstance(cv, list):
        count = len(cv)
    elif isinstance(cv, str) and cv:
        count = len([p.strip() for p in cv.split(",") if p.strip()])
    else:
        return
    if f"({count}" not in finding.message:
        finding.message = f"{finding.message} ({count} policies)"


# -----------------------------------------------------------------------
# Severity overrides: rule_id -> corrected severity.
# The auditor JSON assigns a severity per rule; override here when we want
# a different customer-facing severity.
# -----------------------------------------------------------------------
_SEVERITY_OVERRIDES = {
    "SP-01": "MEDIUM",   # Service Policy No Allow-All: High -> Medium
}


def _override_severity(finding: Finding) -> None:
    """Apply configured severity overrides for specific rules."""
    new_sev = _SEVERITY_OVERRIDES.get(finding.rule_id)
    if new_sev and finding.severity.upper() != new_sev:
        finding.severity = new_sev


CORRECTIONS = [
    _fix_reference_urls,
    _annotate_service_policy_count,
    _override_severity,
]


def apply_corrections(findings: List[Finding]) -> None:
    """Mutates findings in place - call once, right after parsing."""
    for finding in findings:
        for correction in CORRECTIONS:
            correction(finding)


def apply_tls_blindfolded(findings: List[Finding], checklist_answers: dict) -> None:
    """Apply TLS blindfolded checklist answer to CERT-02 findings.

    CERT-02 checks "Certificate Key Blindfolded". The manual checklist
    answer maps to: Yes -> PASS, No -> FAIL, Not Reviewed/N/A -> leave as-is.
    """
    answer = (checklist_answers or {}).get("tls-blindfolded", {}).get("status", "Not Reviewed")
    if answer not in ("Yes", "No"):
        return

    new_status = "PASS" if answer == "Yes" else "FAIL"
    new_message = (
        "TLS certificate is using blindfolded secret for the private key."
        if answer == "Yes"
        else "TLS certificate is NOT using blindfolded secret for the private key - consider migrating to blindfolded secrets."
    )

    for finding in findings:
        if finding.rule_id == "CERT-02" and finding.status.upper() in ("SKIP", "INFO"):
            finding.auditor_status = finding.auditor_status or finding.status
            finding.auditor_message = finding.auditor_message or finding.message
            finding.corrected = True
            finding.correction_reason = "Status derived from manual TLS blindfolded checklist answer."
            finding.status = new_status
            finding.message = new_message
