"""
Service policy classification: auto-detects a policy's purpose from its
name, and lets the report author override the guess.

v2.0: Rule references updated from SEC-* to new IDs.
  - SP-01 = Service Policy No Allow-All
  - SP-02 = No Allow-All IP Prefix
  - AC-01 = Service Policy Applied (replaces SEC-028-LB)
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from models import Finding

# Classification categories
GEO_BLOCKING = "Geo Blocking"
HTTP_METHOD = "HTTP Method Restriction"
WAF_EXCLUSION = "WAF Exclusion"
IP_REPUTATION = "IP Reputation"
CLIENT_SIDE_DEFENSE = "Client-Side Defense"
ALLOW_ALL = "Allow All"
OTHER = "Other"

CLASSIFICATION_OPTIONS = [GEO_BLOCKING, HTTP_METHOD, WAF_EXCLUSION, IP_REPUTATION,
                           CLIENT_SIDE_DEFENSE, ALLOW_ALL, OTHER]

# Auto-detect patterns: ordered most-specific first
_AUTO_PATTERNS = [
    (GEO_BLOCKING, re.compile(r"geo[-_]?block|blacklist")),
    (IP_REPUTATION, re.compile(r"ip[-_]?reputation")),
    (CLIENT_SIDE_DEFENSE, re.compile(r"\bcsd\b|js[-_]?insertion")),
    (HTTP_METHOD, re.compile(r"\buri\b|allowed[-_]uri|method")),
    (ALLOW_ALL, re.compile(r"allow[-_]all")),
]

# WAF exclusion is detected at namespace level, not from LB-linked policy names.
_WAF_EXCLUSION_PREFIX = "ves-io-http-loadbalancer-waf-exclusion-"

# Namespace-level auto-generated service policy prefixes
_IP_REPUTATION_PREFIX = "ves-io-http-loadbalancer-ip-reputation-"
_CSD_PREFIX = "ves-io-http-loadbalancer-csd-js-insertion-policy-"
_TRUSTED_CLIENTS_WAF_PREFIX = "ves-io-http-loadbalancer-trusted-clients-waf-"
_TRUSTED_CLIENTS_IP_REP_PREFIX = "ves-io-http-loadbalancer-trusted-clients-ip-reputation-"
_TRUSTED_CLIENTS_THREAT_INTEL_PREFIX = "ves-io-http-loadbalancer-trusted-clients-threat-intel-"


def auto_classify(policy_name: str) -> str:
    """Guess a service policy's category from its name."""
    name = (policy_name or "").lower()
    for category, pattern in _AUTO_PATTERNS:
        if pattern.search(name):
            return category
    return OTHER


def classify_with_override(policy_name: str, overrides: Optional[Dict[str, str]] = None) -> str:
    if overrides and policy_name in overrides:
        return overrides[policy_name]
    return auto_classify(policy_name)


def classify_lb_policies(policy_names: List[str],
                          overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    return {name: classify_with_override(name, overrides) for name in policy_names}


def group_policies_by_category(policy_names: List[str],
                                policy_findings: List[Finding],
                                overrides: Optional[Dict[str, str]] = None
                                ) -> Dict[str, List[str]]:
    classifications = classify_lb_policies(policy_names, overrides)
    groups: Dict[str, List[str]] = {}
    for name, cat in classifications.items():
        groups.setdefault(cat, []).append(name)
    return groups


def has_waf_exclusion_policies(lb_name: str,
                                all_findings: List[Finding] = None) -> Tuple[bool, List[str]]:
    if not all_findings:
        return False, []
    target = _WAF_EXCLUSION_PREFIX + lb_name
    exclusion_policies = set()
    for f in all_findings:
        if f.object_type == "service_policy" and f.object_name == target:
            exclusion_policies.add(f.object_name)
    return bool(exclusion_policies), sorted(exclusion_policies)


def _get_namespace_sp_findings(lb_name: str, prefix: str,
                                all_findings: List[Finding]) -> List[Finding]:
    if not all_findings:
        return []
    target = prefix + lb_name
    return [f for f in all_findings
            if f.object_type == "service_policy" and f.object_name == target]


def get_ip_reputation_ns_findings(lb_name: str, all_findings: List[Finding]) -> List[Finding]:
    return _get_namespace_sp_findings(lb_name, _IP_REPUTATION_PREFIX, all_findings)


def get_csd_ns_findings(lb_name: str, all_findings: List[Finding]) -> List[Finding]:
    return _get_namespace_sp_findings(lb_name, _CSD_PREFIX, all_findings)


def get_trusted_clients_waf_findings(lb_name: str, all_findings: List[Finding]) -> List[Finding]:
    return _get_namespace_sp_findings(lb_name, _TRUSTED_CLIENTS_WAF_PREFIX, all_findings)


def get_trusted_clients_ip_rep_findings(lb_name: str, all_findings: List[Finding]) -> List[Finding]:
    return _get_namespace_sp_findings(lb_name, _TRUSTED_CLIENTS_IP_REP_PREFIX, all_findings)


def get_trusted_clients_threat_intel_findings(lb_name: str, all_findings: List[Finding]) -> List[Finding]:
    return _get_namespace_sp_findings(lb_name, _TRUSTED_CLIENTS_THREAT_INTEL_PREFIX, all_findings)


def lb_geo_blocking_status(policy_names: List[str],
                            overrides: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    classifications = classify_lb_policies(policy_names, overrides)
    geo_policies = [name for name, cat in classifications.items() if cat == GEO_BLOCKING]
    return bool(geo_policies), geo_policies


def lb_http_method_status(policy_names: List[str],
                           overrides: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    classifications = classify_lb_policies(policy_names, overrides)
    http_policies = [name for name, cat in classifications.items() if cat == HTTP_METHOD]
    return bool(http_policies), http_policies


def filter_findings_by_category(policy_findings: List[Finding],
                                 category: str,
                                 policy_names: List[str],
                                 overrides: Optional[Dict[str, str]] = None) -> List[Finding]:
    classifications = classify_lb_policies(policy_names, overrides)
    matching_names = {name for name, cat in classifications.items() if cat == category}
    return [f for f in policy_findings if f.object_name in matching_names]


# Legacy compatibility
@dataclass
class PolicyApplicability:
    policy_type_guess: str
    applicable: bool
    is_heuristic: bool = True


def guess_policy_type(policy_name: str) -> str:
    return auto_classify(policy_name)


def check_applicability(policy_name: str, rule_id: str) -> PolicyApplicability:
    guessed_type = auto_classify(policy_name)
    _RULE_RELEVANT_TYPES = {
        "SP-01": {ALLOW_ALL},
        "SP-02": {ALLOW_ALL},
    }
    relevant_types = _RULE_RELEVANT_TYPES.get(rule_id)
    if relevant_types is None:
        return PolicyApplicability(guessed_type, applicable=True, is_heuristic=False)
    if guessed_type == OTHER:
        return PolicyApplicability(guessed_type, applicable=True, is_heuristic=True)
    return PolicyApplicability(guessed_type, applicable=guessed_type in relevant_types, is_heuristic=True)


def applicability_with_override(
    policy_name: str, rule_id: str, overrides: Optional[Dict[str, bool]] = None
) -> PolicyApplicability:
    result = check_applicability(policy_name, rule_id)
    if overrides:
        key = f"{policy_name}::{rule_id}"
        if key in overrides:
            return PolicyApplicability(result.policy_type_guess, overrides[key], is_heuristic=False)
    return result
