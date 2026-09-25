"""
Data models for the XC Security Report Generator (v2.0).

These are plain dataclasses - no framework dependency - so they can be
reused by the parser, the relationship engine, the Streamlit UI, and the
HTML export layer without any coupling.

v2.0 changes:
  - Finding: new fields (risk, entitlement, load_balancer, verify, verify_note,
    object_key). Removed: details (no longer in auditor JSON).
  - AuditSummary: new top-level sections (informational, scored_count,
    fetch_errors, namespace_summaries, lb_summaries, entitlement_summary).
  - LoadBalancerReport: simplified — all findings grouped by loadBalancer field.
  - NamespaceReport: simplified — tenant-wide findings use loadBalancer="(tenant-wide)".
"""

from dataclasses import dataclass, field
from typing import List, Any, Optional, Dict


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    category: str

    object_type: str
    object_name: str

    status: str

    message: str

    current_value: Any
    expected_value: Any

    remediation: str
    reference_url: str

    # v2 fields
    risk: str = ""
    entitlement: str = ""           # "Base", "Entitlement", or "Config"
    load_balancer: str = ""         # Direct LB mapping from JSON
    verify: str = ""                # "auto", "assisted", or "manual"
    verify_note: str = ""           # Guidance for manual/assisted verification
    object_key: str = ""            # "namespace/objectName" composite key

    # Set by finding_corrections.py when the raw Security Auditor status/message
    # is known to be misleading and gets systematically corrected.
    corrected: bool = False
    auditor_status: str = None
    auditor_message: str = None
    correction_reason: str = None


@dataclass
class AuditSummary:
    tenant: str
    namespace: str
    namespaces: List[str] = field(default_factory=list)

    timestamp: str = ""
    duration_ms: int = 0

    score: int = 0

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    passed: int = 0
    warnings: int = 0
    errors: int = 0
    skipped: int = 0
    informational: int = 0          # v2: new status category

    scored_count: int = 0           # v2: only scored findings count
    fetch_errors: List[dict] = field(default_factory=list)

    # v2: pre-calculated per-namespace summaries from JSON
    namespace_summaries: List[dict] = field(default_factory=list)
    # v2: pre-calculated per-LB summaries from JSON
    lb_summaries: List[dict] = field(default_factory=list)
    # v2: entitlement breakdown {baseFails, entitlementFails, configFails}
    entitlement_summary: dict = field(default_factory=dict)

    config_snapshot: dict = field(default_factory=dict)


@dataclass
class LoadBalancerReport:
    """
    One HTTP Load Balancer and all findings linked to it via the
    loadBalancer field in the v2 auditor JSON.

    v2.0: No more heuristic matching — the JSON provides direct
    loadBalancer→finding links for every finding.
    """
    name: str
    namespace: str = ""

    # All findings for this LB, grouped by category for convenience
    lb_findings: List[Finding] = field(default_factory=list)

    waf_policy_name: Optional[str] = None
    waf_assigned: bool = False
    waf_mode: Optional[str] = None          # v2: WAFP-01 tells us the mode directly

    waf_policy_findings: List[Finding] = field(default_factory=list)  # v2: WAFP-* linked directly

    service_policy_names: List[str] = field(default_factory=list)
    service_policy_findings: List[Finding] = field(default_factory=list)

    origin_findings: List[Finding] = field(default_factory=list)
    origin_pool_names: List[str] = field(default_factory=list)
    origin_match_is_heuristic: bool = False  # v2: always direct, no heuristic

    certificate_findings: List[Finding] = field(default_factory=list)
    health_check_findings: List[Finding] = field(default_factory=list)
    other_findings: List[Finding] = field(default_factory=list)

    # v2: per-LB score from loadBalancerSummary
    score: Optional[int] = None
    total_checks: int = 0
    pass_count: int = 0
    fail_count: int = 0
    warn_count: int = 0


@dataclass
class NamespaceReport:
    """
    v2.0: Tenant-wide findings (loadBalancer="(tenant-wide)") and any
    findings that are namespace-level rather than LB-specific.
    """
    tenant_findings: List[Finding] = field(default_factory=list)
    waf_policy_findings: List[Finding] = field(default_factory=list)

    orphan_service_policy_findings: List[Finding] = field(default_factory=list)
    orphan_origin_pool_findings: List[Finding] = field(default_factory=list)

    log_receiver_findings: List[Finding] = field(default_factory=list)
    alert_policy_findings: List[Finding] = field(default_factory=list)
    alert_receiver_findings: List[Finding] = field(default_factory=list)
    user_identification_findings: List[Finding] = field(default_factory=list)

    other_findings: List[Finding] = field(default_factory=list)
