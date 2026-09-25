"""
Product entitlement handling for the v2.0 auditor JSON.

v2.0: The JSON now includes an `entitlement` field on every finding:
  - "Base"        -> included in base XC license (always show)
  - "Config"      -> configuration best practice (always show)
  - "Entitlement" -> requires additional license/purchase

The UI still lets the report author toggle which add-on products the
customer has purchased. When a product is unchecked, findings with
entitlement="Entitlement" for those rule IDs move to Additional
Opportunities instead of showing as failures.

Rule IDs for product-gated features (v2):
  - Bot Defense:    BOT-01, BOT-04
  - MUD:            BOT-02, BOT-03
  - API Protection: API-03, API-04, API-06
  - CSD:            CSD-01, CSD-02
  - Rate Limiting:  RL-01, RL-02
  - WAF Malware:    WAF-03
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple

from models import Finding


@dataclass
class Product:
    id: str
    label: str
    rule_ids: List[str]


PRODUCTS: List[Product] = [
    Product(id="bot_defense", label="Bot Defense", rule_ids=["BOT-01", "BOT-04"]),
    Product(id="mud", label="Malicious User Detection (MUD)", rule_ids=["BOT-02", "BOT-03"]),
    Product(id="api_protection", label="API Protection", rule_ids=["API-01", "API-02", "API-03", "API-04", "API-05", "API-06", "API-07"]),
    Product(id="client_side_defense", label="Client-Side Defense", rule_ids=["CSD-01", "CSD-02"]),
    Product(id="rate_limiting", label="Rate Limiting", rule_ids=["RL-01", "RL-02"]),
    Product(id="malware_protection", label="Malware Protection", rule_ids=["WAF-03"]),
]

_RULE_TO_PRODUCT: Dict[str, Product] = {
    rule_id: product for product in PRODUCTS for rule_id in product.rule_ids
}


def default_entitlements() -> Dict[str, bool]:
    """Default: assume everything is purchased."""
    return {product.id: True for product in PRODUCTS}


def product_for_rule(rule_id: str) -> Product:
    return _RULE_TO_PRODUCT.get(rule_id)


def is_gated(rule_id: str) -> bool:
    """True if this rule belongs to a separately-purchasable product."""
    return rule_id in _RULE_TO_PRODUCT


def is_entitled(finding: Finding, entitlements: Dict[str, bool]) -> bool:
    """True if this finding is either not product-gated at all, or the
    customer has that product."""
    product = product_for_rule(finding.rule_id)
    if product is None:
        return True
    return entitlements.get(product.id, True)


def split_findings(
    findings: List[Finding], entitlements: Dict[str, bool]
) -> Tuple[List[Finding], List[Finding]]:
    """Splits a finding list into (entitled_or_ungated, not_purchased)."""
    entitled, not_purchased = [], []
    for f in findings:
        if is_entitled(f, entitlements):
            entitled.append(f)
        else:
            not_purchased.append(f)
    return entitled, not_purchased
