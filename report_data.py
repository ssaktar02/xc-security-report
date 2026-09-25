"""
Turns parsed models (AuditSummary, LoadBalancerReport, NamespaceReport) into
plain dicts/lists for rendering. v2.0 uses loadBalancerSummary from JSON
when available, falls back to calculation.
"""

from collections import Counter
from typing import List

from models import AuditSummary, LoadBalancerReport, NamespaceReport, Finding

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def namespace_summary(summary: AuditSummary, reports: dict) -> dict:
    return {
        "tenant": summary.tenant,
        "namespace": summary.namespace,
        "timestamp": summary.timestamp,
        "score": summary.score,
        "total": summary.total,
        "critical": summary.critical,
        "high": summary.high,
        "medium": summary.medium,
        "low": summary.low,
        "info": summary.info,
        "passed": summary.passed,
        "warnings": summary.warnings,
        "errors": summary.errors,
        "skipped": summary.skipped,
        "load_balancers": len(reports),
    }


def _health_from_severity_counts(severity: Counter, total_checks: int = 0, passed_checks: int = 0) -> tuple:
    if severity["CRITICAL"] > 0:
        return "Action Needed", "🔴"
    if severity["HIGH"] > 0:
        return "Needs Attention", "🟠"
    if severity["MEDIUM"] > 0:
        return "Fair", "🟡"
    if total_checks > 0:
        return f"{passed_checks} of {total_checks} Checks Passed", "🟢"
    return "Healthy", "🟢"


HEALTH_COLORS = {
    "Action Needed": "#c0392b",
    "Needs Attention": "#e67e22",
    "Fair": "#c9a227",
    "Healthy": "#27ae60",
}


def health_color(health_label: str) -> str:
    if "Checks Passed" in health_label:
        return "#27ae60"
    return HEALTH_COLORS.get(health_label, "#27ae60")


def namespace_summary_entitled(summary: AuditSummary, reports: dict, all_findings: List[Finding], entitlements: dict) -> dict:
    from product_entitlements import split_findings

    entitled, _ = split_findings(all_findings, entitlements)
    fail_only = [f for f in entitled if f.status.upper() == "FAIL"]
    severity = Counter(f.severity.upper() for f in fail_only)

    base = namespace_summary(summary, reports)
    base.update({
        "critical": severity["CRITICAL"],
        "high": severity["HIGH"],
        "medium": severity["MEDIUM"],
        "low": severity["LOW"],
    })
    return base


def lb_summary(lb: LoadBalancerReport, checklist_answers: dict = None,
               not_purchased_findings: List[Finding] = None) -> dict:
    """Executive summary for an LB."""
    all_findings = lb_all_findings(lb)

    severity = Counter()
    status = Counter()

    for finding in all_findings:
        status[finding.status.upper()] += 1
        if finding.status.upper() in ("FAIL", "WARN"):
            severity[finding.severity.upper()] += 1

    passed = status["PASS"]
    informational = status["INFO"] + status["SKIP"]

    # Fold in manual checklist items
    from manual_checklist import MANUAL_CHECKLIST_ITEMS
    checklist_answers = checklist_answers or {}
    for item in MANUAL_CHECKLIST_ITEMS:
        answer = checklist_answers.get(item.id, {}).get("status", "Not Reviewed")
        if answer == "Yes":
            passed += 1
        elif answer == "No":
            severity["MEDIUM"] += 1
        else:
            informational += 1

    # Fold in geo-blocking and HTTP method restriction checks
    from policy_type import lb_geo_blocking_status, lb_http_method_status
    has_geo, _ = lb_geo_blocking_status(lb.service_policy_names)
    has_http, _ = lb_http_method_status(lb.service_policy_names)
    if has_geo:
        passed += 1
    else:
        severity["MEDIUM"] += 1
    if has_http:
        passed += 1
    else:
        informational += 1

    # Fold in additional opportunities as informational
    if not_purchased_findings:
        not_purchased_open = [f for f in not_purchased_findings if f.status.upper() != "PASS"]
        informational += len(not_purchased_open)

    total = (severity["CRITICAL"] + severity["HIGH"] + severity["MEDIUM"] +
             severity["LOW"] + passed + informational)
    health, icon = _health_from_severity_counts(severity, total, passed)

    # v2: Use WAF mode from WAFP-01 if available
    waf_mode_display = lb.waf_mode or "Not Set"

    return {
        "name": lb.name,
        "health": health,
        "health_icon": icon,
        "critical": severity["CRITICAL"],
        "high": severity["HIGH"],
        "medium": severity["MEDIUM"],
        "low": severity["LOW"],
        "passed": passed,
        "informational": informational,
        "total": total,
        "waf_policy_name": lb.waf_policy_name or "None",
        "waf_assigned": lb.waf_assigned,
        "waf_mode": waf_mode_display,
        "service_policy_count": len(lb.service_policy_names),
        "origin_pool_count": len(lb.origin_pool_names),
        "score": lb.score,
    }


def group_findings_by_severity(findings: List[Finding]) -> dict:
    grouped = {sev: [] for sev in SEVERITY_ORDER}
    grouped["PASS"] = []

    for finding in findings:
        if finding.status.upper() == "PASS":
            grouped["PASS"].append(finding)
            continue
        sev = finding.severity.upper()
        grouped.setdefault(sev, [])
        grouped[sev].append(finding)

    return grouped


def recommendations(findings: List[Finding]) -> list:
    rec = []
    seen = set()
    order = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings, key=lambda f: order.get(f.severity.upper(), len(order))
    )

    for finding in sorted_findings:
        if finding.status.upper() == "PASS":
            continue
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)

        rec.append({
            "rule_id": finding.rule_id,
            "rule": finding.rule_name,
            "severity": finding.severity,
            "category": finding.category,
            "message": finding.message,
            "recommendation": finding.remediation,
            "reference": finding.reference_url,
        })

    return rec


def lb_all_findings(lb: LoadBalancerReport) -> List[Finding]:
    """All findings attributable to this LB."""
    return (
        lb.lb_findings
        + lb.waf_policy_findings
        + lb.service_policy_findings
        + lb.origin_findings
        + lb.certificate_findings
        + lb.health_check_findings
        + lb.other_findings
    )


def namespace_all_findings(ns: NamespaceReport) -> List[Finding]:
    return (
        ns.tenant_findings
        + ns.waf_policy_findings
        + ns.orphan_service_policy_findings
        + ns.orphan_origin_pool_findings
        + ns.log_receiver_findings
        + ns.alert_policy_findings
        + ns.alert_receiver_findings
        + ns.user_identification_findings
        + ns.other_findings
    )


STATUS_COLORS = {
    "PASS": "#27ae60",
    "SKIP": "#95a5a6",
    "INFO": "#5b7a9a",
    "WARN": "#e67e22",
}

FAIL_SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e2231a",
    "MEDIUM": "#e67e22",
    "LOW": "#c9a227",
    "INFO": "#5b7a9a",
}


def status_badge_color(status: str, severity: str) -> str:
    status_u = (status or "").upper()
    if status_u == "FAIL":
        return FAIL_SEVERITY_COLORS.get((severity or "").upper(), "#e2231a")
    return STATUS_COLORS.get(status_u, "#999999")


# Customer-facing display labels for internal status values.
# Underlying status values (FAIL/WARN) are unchanged for all logic/filtering.
STATUS_DISPLAY_LABELS = {
    "FAIL": "REVIEW",
    "WARN": "CAUTION",
}


def status_display_label(status: str) -> str:
    status_u = (status or "").upper()
    return STATUS_DISPLAY_LABELS.get(status_u, status_u)


def lb_summary_entitled(lb: LoadBalancerReport, entitlements: dict,
                        checklist_answers: dict = None) -> dict:
    from product_entitlements import split_findings

    all_findings = lb_all_findings(lb)
    entitled_findings, not_purchased = split_findings(all_findings, entitlements)
    not_purchased_open = [f for f in not_purchased if f.status.upper() != "PASS"]

    severity = Counter()
    status = Counter()
    for finding in entitled_findings:
        status[finding.status.upper()] += 1
        if finding.status.upper() in ("FAIL", "WARN"):
            severity[finding.severity.upper()] += 1

    passed = status["PASS"]
    informational = status["INFO"] + status["SKIP"]

    from manual_checklist import MANUAL_CHECKLIST_ITEMS
    checklist_answers = checklist_answers or {}
    for item in MANUAL_CHECKLIST_ITEMS:
        answer = checklist_answers.get(item.id, {}).get("status", "Not Reviewed")
        if answer == "Yes":
            passed += 1
        elif answer == "No":
            severity["MEDIUM"] += 1
        else:
            informational += 1

    from policy_type import lb_geo_blocking_status, lb_http_method_status
    has_geo, _ = lb_geo_blocking_status(lb.service_policy_names)
    has_http, _ = lb_http_method_status(lb.service_policy_names)
    if has_geo:
        passed += 1
    else:
        severity["MEDIUM"] += 1
    if has_http:
        passed += 1
    else:
        informational += 1

    informational += len(not_purchased_open)

    total = (severity["CRITICAL"] + severity["HIGH"] + severity["MEDIUM"] +
             severity["LOW"] + passed + informational)
    health, icon = _health_from_severity_counts(severity, total, passed)

    base = lb_summary(lb, checklist_answers=checklist_answers,
                      not_purchased_findings=not_purchased)
    base.update({
        "health": health,
        "health_icon": icon,
        "critical": severity["CRITICAL"],
        "high": severity["HIGH"],
        "medium": severity["MEDIUM"],
        "low": severity["LOW"],
        "passed": passed,
        "informational": informational,
        "total": total,
    })
    return base
