"""
Manual review checklist items (v2.0).

v2.0: Several items are now auto-covered by TENANT-* rules in the JSON:
  - TENANT-ALERT-01: Alert Policies Configured
  - TENANT-LOG-01/02: SIEM/GLR
  - TENANT-IAM-01: Credential Expiry
  - TENANT-IAM-02: Stale Credentials
  - TENANT-IAM-03: SSO + MFA
  - TENANT-IAM-04: Session Timeouts

Remaining manual items: WAAP report review, synthetic monitoring,
console IP restriction, tenancy IP restriction, TLS blindfolded.
Console MFA is now auto-checked by TENANT-IAM-03 so removed from manual.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class ManualChecklistItem:
    id: str
    label: str
    short_name: str = ""
    guidance: str = ""
    recommendation: str = ""
    reference_url: str = ""


MANUAL_CHECKLIST_ITEMS = [
    ManualChecklistItem(
        id="waap-report-review",
        label="Is the XC WAAP Report being used regularly to monitor traffic, threats, and policy effectiveness?",
        short_name="WAAP Report Review",
        guidance="Confirm with the customer how often they review the WAAP report and who owns that review.",
        recommendation=(
            "Set up & regularly review WAAP reports to identify trends, fine-tune policies, and ensure threat visibility.\n"
            "The reporting feature provides periodic overview snapshots (reports) for security incidents with WAF & Bot Defense."
        ),
        reference_url="https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/others/reports",
    ),
    ManualChecklistItem(
        id="synthetic-monitoring",
        label="Is Synthetic Monitoring being used to track application health and availability?",
        short_name="Synthetic Monitoring",
        guidance="Check whether synthetic monitors are configured for the application's critical paths.",
        recommendation=(
            "Implement Synthetic Monitoring to simulate user interactions and continuously test application availability and response."
        ),
        reference_url="https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
    ),
    ManualChecklistItem(
        id="console-ip-restriction",
        label="Is access to the F5 Distributed Cloud Console restricted to specific IP addresses or ranges?",
        short_name="Console IP Restriction",
        guidance="Review tenant-level console access policy with the customer's XC admin.",
        recommendation=(
            "If available for your tenant, restrict console access to trusted office IPs, VPN ranges, or known management networks only.\n"
            "Please raise a ticket with F5 support to help with it.\n"
            "Restricting console access reduces the attack surface and helps prevent unauthorized access attempts from the public internet."
        ),
        reference_url="https://docs.cloud.f5.com/docs-v2/support/tnt-restrctn",
    ),
    ManualChecklistItem(
        id="tenancy-ip-restriction",
        label="Is Tenancy IP restriction configured?",
        short_name="Tenancy IP Restriction",
        guidance="Review the tenant-wide IP allowlist configuration.",
        recommendation=(
            "Open a support ticket specifying the access restriction by IP/ASN/Region. "
            "Once ticket is submitted, the F5 support team provisions the access with restrictions in place."
        ),
        reference_url="https://docs.cloud.f5.com/docs-v2/support/tnt-restrctn",
    ),
    ManualChecklistItem(
        id="tls-blindfolded",
        label="Is the TLS certificate using blindfolded secret for the private key?",
        short_name="TLS Certificate Blindfolded",
        guidance="Check if TLS certificates use F5 XC blindfolded secrets instead of clear-text private keys.",
        recommendation=(
            "Use blindfolded secrets for TLS certificate private keys. "
            "Blindfolded secrets encrypt the private key so it is never exposed in clear text, "
            "even to F5 XC administrators. This ensures the key material is protected at rest and in transit."
        ),
        reference_url="https://docs.cloud.f5.com/docs-v2/administration/how-tos/user-mgmt/general-management",
    ),
]

# WAF Enforcement Mode recommendation
WAF_MODE_RECOMMENDATION = (
    "Ensure WAF is in Blocking mode in production environments to actively stop malicious traffic.\n\n"
    "Recommended best practice:\n"
    "- All Attack signatures are active\n"
    "- High & medium accuracy signatures are enabled\n\n"
    "More aggressive settings is to enable all (High, Medium & Low) signatures but that introduces "
    "higher risk of false positives, so proper testing is required in that case.\n\n"
    "Blocking mode ensures that identified threats (e.g., SQLi, XSS, command injection) are not just "
    "logged but also prevented in real-time."
)
WAF_MODE_REFERENCE_URL = "https://my.f5.com/manage/s/article/K000156593"

WAF_EXCLUSION_RECOMMENDATION = (
    "Review WAF exclusion rules to ensure they are not overly broad. "
    "Check signature IDs and their details to verify each exclusion is still necessary and appropriately scoped."
)
WAF_EXCLUSION_REFERENCE_URL = "https://docs.cloud.f5.com/docs-v2/platform/reference/attack-signatures"

STATUS_OPTIONS = ["Not Reviewed", "Yes", "No", "N/A"]


def default_answers() -> Dict[str, dict]:
    return {
        item.id: {"status": "Not Reviewed", "notes": ""}
        for item in MANUAL_CHECKLIST_ITEMS
    }
