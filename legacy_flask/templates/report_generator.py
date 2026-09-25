from collections import Counter


class ReportGenerator:

    def __init__(self, summary, reports):
        self.summary = summary
        self.reports = reports

    def namespace_summary(self):
        return {
            "tenant": self.summary.tenant,
            "namespace": self.summary.namespace,
            "score": self.summary.score,
            "total": self.summary.total,
            "critical": self.summary.critical,
            "high": self.summary.high,
            "medium": self.summary.medium,
            "low": self.summary.low,
            "passed": self.summary.passed,
            "warnings": self.summary.warnings,
            "errors": self.summary.errors,
            "skipped": self.summary.skipped,
            "load_balancers": len(self.reports),
        }

    def lb_summary(self, lb):

        severity = Counter()
        status = Counter()

        for finding in lb.lb_findings:
            severity[finding.severity.upper()] += 1
            status[finding.status.upper()] += 1

        if severity["CRITICAL"] > 0:
            health = "Critical"
            color = "danger"
        elif severity["HIGH"] > 0:
            health = "Needs Attention"
            color = "warning"
        else:
            health = "Healthy"
            color = "success"

        return {
            "name": lb.name,
            "health": health,
            "health_color": color,
            "critical": severity["CRITICAL"],
            "high": severity["HIGH"],
            "medium": severity["MEDIUM"],
            "low": severity["LOW"],
            "info": severity["INFO"],
            "passed": status["PASS"],
            "failed": status["FAIL"],
            "warning": status["WARN"],
            "skipped": status["SKIP"],
            "total": len(lb.lb_findings)
        }

    def group_findings(self, lb):

        grouped = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
            "PASS": []
        }

        for finding in lb.lb_findings:

            if finding.status.upper() == "PASS":
                grouped["PASS"].append(finding)
                continue

            sev = finding.severity.upper()

            if sev not in grouped:
                grouped[sev] = []

            grouped[sev].append(finding)

        return grouped

    def recommendations(self, lb):

        rec = []

        seen = set()

        for finding in lb.lb_findings:

            if finding.status.upper() == "PASS":
                continue

            if finding.rule_id in seen:
                continue

            seen.add(finding.rule_id)

            rec.append({
                "rule": finding.rule_name,
                "severity": finding.severity,
                "recommendation": finding.remediation,
                "reference": finding.reference_url
            })

        return rec