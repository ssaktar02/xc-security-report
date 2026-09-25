"""
Parses a raw F5 XC Security Auditor JSON export (v2.0 format) into an
AuditSummary and a flat list of Finding objects.

v2.0 changes:
  - Rule IDs changed from SEC-* to categorized prefixes (WAF-01, TLS-01, etc.)
  - New finding fields: risk, entitlement, loadBalancer, verify, verifyNote, objectKey
  - Removed: details field
  - New top-level: loadBalancerSummary, namespaceSummary, entitlementSummary, scoredCount, fetchErrors
"""

import json

from models import Finding, AuditSummary
from finding_corrections import apply_corrections


class AuditParseError(ValueError):
    """Raised when the uploaded file doesn't look like a Security Auditor export."""
    pass


class AuditParser:

    REQUIRED_TOP_LEVEL_KEYS = ("tenant", "namespaces", "summary", "findings")

    def __init__(self, json_path_or_file):
        self.json_path_or_file = json_path_or_file

    def _load_raw(self) -> dict:
        source = self.json_path_or_file

        if hasattr(source, "read"):
            raw = source.read()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            data = json.loads(raw)
        else:
            with open(source, "r", encoding="utf-8") as file:
                data = json.load(file)

        missing = [key for key in self.REQUIRED_TOP_LEVEL_KEYS if key not in data]
        if missing:
            raise AuditParseError(
                "This doesn't look like a Security Auditor JSON export. "
                f"Missing expected field(s): {', '.join(missing)}"
            )

        return data

    def parse(self):
        data = self._load_raw()

        summary_block = data.get("summary", {})
        all_namespaces = data.get("namespaces") or ["unknown"]

        summary = AuditSummary(
            tenant=data.get("tenant", "unknown"),
            namespace=all_namespaces[0],
            namespaces=all_namespaces,
            timestamp=data.get("timestamp", ""),
            duration_ms=data.get("durationMs", 0),
            score=data.get("score", 0),

            total=summary_block.get("total", 0),
            critical=summary_block.get("critical", 0),
            high=summary_block.get("high", 0),
            medium=summary_block.get("medium", 0),
            low=summary_block.get("low", 0),
            info=summary_block.get("info", 0),

            passed=summary_block.get("passed", 0),
            warnings=summary_block.get("warnings", 0),
            errors=summary_block.get("errors", 0),
            skipped=summary_block.get("skipped", 0),
            informational=summary_block.get("informational", 0),

            scored_count=data.get("scoredCount", 0),
            fetch_errors=data.get("fetchErrors", []),

            namespace_summaries=data.get("namespaceSummary", []),
            lb_summaries=data.get("loadBalancerSummary", []),
            entitlement_summary=data.get("entitlementSummary", {}),

            config_snapshot=data.get("configSnapshot", {}) or {},
        )

        findings = []

        for item in data.get("findings", []):
            findings.append(
                Finding(
                    rule_id=item.get("ruleId", ""),
                    rule_name=item.get("ruleName", ""),
                    severity=item.get("severity", "INFO"),
                    category=item.get("category", "UNCATEGORIZED"),

                    object_type=item.get("objectType", "unknown"),
                    object_name=item.get("objectName", "unknown"),

                    status=item.get("status", "UNKNOWN"),

                    message=item.get("message", ""),

                    current_value=item.get("currentValue", ""),
                    expected_value=item.get("expectedValue", ""),

                    remediation=item.get("remediation", ""),
                    reference_url=item.get("referenceUrl", ""),

                    # v2 fields
                    risk=item.get("risk", ""),
                    entitlement=item.get("entitlement", ""),
                    load_balancer=item.get("loadBalancer", ""),
                    verify=item.get("verify", ""),
                    verify_note=item.get("verifyNote", ""),
                    object_key=item.get("objectKey", ""),
                )
            )

        apply_corrections(findings)

        return summary, findings
