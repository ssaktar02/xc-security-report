"""
Builds Load Balancer reports and a Namespace report from a flat list of
Findings (v2.0).

v2.0: The auditor JSON now includes a `loadBalancer` field on every finding,
providing direct LB-to-finding mapping. No more heuristic origin pool
matching or service policy name extraction from currentValue. The
RelationshipBuilder simply groups findings by their loadBalancer field.

Tenant-wide findings use loadBalancer="(tenant-wide)".
"""

from typing import Dict, List, Tuple

from models import Finding, AuditSummary, LoadBalancerReport, NamespaceReport

TENANT_LB_NAME = "(tenant-wide)"

# v2 rule IDs for extracting specific info
RULE_WAF_ATTACHED = "WAF-01"
RULE_WAF_MODE = "WAFP-01"
RULE_SERVICE_POLICY = "AC-01"
RULE_HEALTH_CHECK = "HC-01"


class RelationshipBuilder:

    def __init__(self, findings: List[Finding], summary: AuditSummary = None):
        self.findings = findings
        self.summary = summary

    def build(self) -> Tuple[Dict[str, LoadBalancerReport], NamespaceReport]:
        # Group all findings by loadBalancer field
        by_lb: Dict[str, List[Finding]] = {}
        for f in self.findings:
            lb_name = f.load_balancer or "(unknown)"
            by_lb.setdefault(lb_name, []).append(f)

        # Separate tenant-wide findings
        tenant_findings = by_lb.pop(TENANT_LB_NAME, [])
        unknown_findings = by_lb.pop("(unknown)", [])

        # Build LB reports
        reports: Dict[str, LoadBalancerReport] = {}

        # Pre-index LB summaries from JSON for score lookup
        lb_score_map = {}
        if self.summary and self.summary.lb_summaries:
            for lbs in self.summary.lb_summaries:
                key = lbs.get("loadBalancer", "")
                lb_score_map[key] = lbs

        for lb_name, findings_list in by_lb.items():
            report = LoadBalancerReport(name=lb_name)

            # Determine namespace from first finding
            if findings_list:
                report.namespace = findings_list[0].object_key.split("/")[0] if "/" in (findings_list[0].object_key or "") else findings_list[0].namespace if hasattr(findings_list[0], 'namespace') else ""

            # Categorize findings
            for f in findings_list:
                obj_type = (f.object_type or "").lower()
                rule_id = f.rule_id

                if obj_type == "healthcheck" or rule_id == RULE_HEALTH_CHECK:
                    report.health_check_findings.append(f)
                elif obj_type == "origin_pool":
                    report.origin_findings.append(f)
                    if f.object_name not in report.origin_pool_names:
                        report.origin_pool_names.append(f.object_name)
                elif obj_type == "app_firewall":
                    report.waf_policy_findings.append(f)
                elif obj_type == "service_policy":
                    report.service_policy_findings.append(f)
                elif obj_type == "certificate":
                    report.certificate_findings.append(f)
                elif obj_type in ("global_log_receiver", "alert_policy", "alert_receiver"):
                    report.other_findings.append(f)
                elif obj_type == "http_loadbalancer":
                    report.lb_findings.append(f)
                else:
                    report.lb_findings.append(f)

            # Extract WAF info from WAF-01 finding
            waf_finding = next(
                (f for f in report.lb_findings if f.rule_id == RULE_WAF_ATTACHED), None
            )
            if waf_finding:
                current = waf_finding.current_value
                if current and str(current).lower() not in ("unknown", ""):
                    report.waf_policy_name = str(current)
                    report.waf_assigned = waf_finding.status.upper() == "PASS"
                else:
                    report.waf_assigned = False

            # Extract WAF mode from WAFP-01 finding
            waf_mode_finding = next(
                (f for f in report.waf_policy_findings if f.rule_id == RULE_WAF_MODE), None
            )
            if waf_mode_finding:
                cv = waf_mode_finding.current_value
                if cv and str(cv).upper() in ("BLOCKING", "MONITORING"):
                    report.waf_mode = str(cv).title()

            # Extract service policy names from AC-01
            sp_finding = next(
                (f for f in report.lb_findings if f.rule_id == RULE_SERVICE_POLICY), None
            )
            if sp_finding:
                cv = sp_finding.current_value
                if isinstance(cv, list):
                    report.service_policy_names = cv
                elif isinstance(cv, str) and cv:
                    report.service_policy_names = [p.strip() for p in cv.split(",") if p.strip()]

            # Apply per-LB scores from loadBalancerSummary
            lbs_data = lb_score_map.get(lb_name, {})
            if lbs_data:
                report.score = lbs_data.get("score")
                report.total_checks = lbs_data.get("total", 0)
                report.pass_count = lbs_data.get("pass", 0)
                report.fail_count = lbs_data.get("fail", 0)
                report.warn_count = lbs_data.get("warn", 0)

            reports[lb_name] = report

        # Namespace report: tenant-wide + any unknown/unmatched findings
        namespace_report = NamespaceReport(
            tenant_findings=tenant_findings,
            other_findings=unknown_findings,
        )

        # Categorize tenant findings into sub-lists for alert/log/etc
        for f in tenant_findings:
            rid = f.rule_id or ""
            if rid == "TENANT-ALERT-01":
                namespace_report.alert_policy_findings.append(f)
            elif rid in ("TENANT-LOG-01", "TENANT-LOG-02"):
                namespace_report.log_receiver_findings.append(f)

        return reports, namespace_report
