"""
XC Security Report Generator - Streamlit app.

Upload an F5 XC Security Auditor JSON export and get a browsable dashboard,
a per-Load-Balancer report, and a namespace-wide report, with HTML
downloads for each.

Run with:  streamlit run app.py
"""

import io
import zipfile
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from parser import AuditParser, AuditParseError
from relationship import RelationshipBuilder
import report_data as rd
import html_export as he
import pdf_export
import docx_export
from manual_checklist import MANUAL_CHECKLIST_ITEMS, STATUS_OPTIONS, default_answers
from product_entitlements import PRODUCTS, default_entitlements, split_findings
from finding_corrections import apply_tls_blindfolded
import policy_type as pt

WAF_MODE_OPTIONS = ["Not Set", "Blocking", "Monitoring", "N/A - No WAF Assigned"]

st.set_page_config(
    page_title="XC Security Report Generator",
    page_icon="🛡️",
    layout="wide",
)

# ----------------------------------------------------------------------
# Session state
# ----------------------------------------------------------------------
if "summary" not in st.session_state:
    st.session_state.summary = None
    st.session_state.reports = {}
    st.session_state.namespace_report = None
    st.session_state.source_name = None
    st.session_state.checklist_answers = default_answers()
    st.session_state.all_findings = []
    st.session_state.entitlements = default_entitlements()
    st.session_state.edited_messages = {}
    st.session_state.policy_overrides = {}
    st.session_state.waf_modes = {}
    st.session_state.policy_classifications = {}

if "show_timestamp" not in st.session_state:
    st.session_state.show_timestamp = True
if "show_trusted_clients" not in st.session_state:
    st.session_state.show_trusted_clients = False
if "excluded_findings" not in st.session_state:
    st.session_state.excluded_findings = set()  # keys of findings excluded from export


def _load_file(uploaded_file):
    try:
        summary, findings = AuditParser(uploaded_file).parse()
    except AuditParseError as e:
        st.error(str(e))
        return
    except Exception as e:
        st.error(f"Couldn't parse this file: {e}")
        return

    reports, namespace_report = RelationshipBuilder(findings, summary).build()

    st.session_state.summary = summary
    st.session_state.reports = reports
    st.session_state.namespace_report = namespace_report
    st.session_state.source_name = uploaded_file.name
    st.session_state.selected_lb = None
    st.session_state.checklist_answers = default_answers()
    st.session_state.all_findings = findings
    st.session_state.entitlements = default_entitlements()
    st.session_state.edited_messages = {}
    st.session_state.policy_overrides = {}
    st.session_state.waf_modes = {}
    st.session_state.policy_classifications = {}


def _finding_key(f) -> str:
    return f"{f.rule_id}::{f.object_name}"


def _status_dot(status: str, severity: str) -> str:
    color = rd.status_badge_color(status, severity)
    return f'<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{color};margin-right:6px;"></span>'


def _health_badge(health: str, icon: str):
    color = rd.health_color(health)
    st.markdown(f"### <span style='color:{color}'>{icon} {health}</span>", unsafe_allow_html=True)


def render_editable_findings_table(findings, key_prefix, show_object=True, show_applicability=False):
    """
    Renders findings as styled rows with per-finding expandable recommendations.
    - FAIL/WARN/ERROR findings: expander open by default showing recommendation
    - PASS/INFO/SKIP/NONE findings: expander closed, click to see best practice
    - Delete toggle on the right side of each row (outside expander)
    """
    if not findings:
        st.caption("No findings in this category.")
        return

    _STATUS_ICONS = {
        "PASS": "✅", "FAIL": "❌", "WARN": "⚠️",
        "ERROR": "🔴", "INFO": "ℹ️", "SKIP": "⏭️",
        "NONE": "➖",
    }

    seen_uids = {}
    for idx, f in enumerate(findings):
        key = _finding_key(f)
        # Stable, order-independent widget UID (idx-based keys caused edited
        # messages/exclusions to shift onto the wrong finding when the list
        # re-ordered). A per-list occurrence counter guarantees uniqueness
        # even in the unlikely event two findings share the same key.
        occ = seen_uids.get(key, 0)
        seen_uids[key] = occ + 1
        uid = f"{key}__{occ}"
        original = f.auditor_message if f.corrected else f.message
        current_message = st.session_state.edited_messages.get(key, f.message)
        is_edited = current_message != original
        status_upper = f.status.upper()
        icon = _STATUS_ICONS.get(status_upper, "➖")

        # Determine if expander should be open by default
        auto_expand = status_upper in ("FAIL", "WARN", "ERROR")

        # Build the expander label
        edited_marker = " ✏️" if is_edited else ""
        excluded_marker = " 🚫" if key in st.session_state.excluded_findings else ""
        obj_text = f" | {f.object_name}" if show_object and f.object_name else ""
        label = f"{rd.status_display_label(status_upper)} | {f.severity.upper()} | {f.rule_name} ({f.rule_id}){obj_text}{edited_marker}{excluded_marker}"

        # Row: expander (left, wide) + delete toggle (right, narrow)
        col_exp, col_del = st.columns([20, 1])
        with col_del:
            included = key not in st.session_state.excluded_findings
            keep = st.checkbox("✓", value=included, key=f"incl_{key_prefix}_{uid}",
                               label_visibility="collapsed")
            if not keep:
                st.session_state.excluded_findings.add(key)
            elif key in st.session_state.excluded_findings:
                st.session_state.excluded_findings.discard(key)

        with col_exp:
            exp_icon = "⚠️" if auto_expand else icon
            with st.expander(label, expanded=auto_expand, icon=exp_icon):
                # Message display
                st.markdown(f"**Finding:** {current_message}")

                # Editable message
                new_msg = st.text_area(
                    "Edit message (internal only — reflected in HTML export)",
                    value=current_message,
                    key=f"msg_{key_prefix}_{uid}",
                    height=68,
                    label_visibility="collapsed",
                )
                if new_msg != original:
                    st.session_state.edited_messages[key] = new_msg
                elif key in st.session_state.edited_messages:
                    del st.session_state.edited_messages[key]

                # Applicability override (service policy tables)
                if show_applicability:
                    override_key = f"{f.object_name}::{f.rule_id}"
                    heuristic = pt.check_applicability(f.object_name, f.rule_id)
                    current_appl = st.session_state.policy_overrides.get(override_key, heuristic.applicable)
                    new_appl = st.checkbox(
                        "Applicable", value=current_appl, key=f"appl_{key_prefix}_{uid}",
                    )
                    if new_appl != heuristic.applicable:
                        st.session_state.policy_overrides[override_key] = new_appl
                    elif override_key in st.session_state.policy_overrides:
                        del st.session_state.policy_overrides[override_key]

                # Recommendation / Best Practice
                st.divider()
                if status_upper in ("FAIL", "WARN", "ERROR"):
                    if f.remediation:
                        st.warning(f"**Recommendation:** {f.remediation}")
                    else:
                        st.warning("**Recommendation:** Review this finding and take corrective action.")
                else:
                    if f.remediation:
                        st.info(f"**Best Practice:** {f.remediation}")
                    else:
                        st.info(f"**Best Practice:** This check passed. No action required — continue monitoring.")

                if f.reference_url:
                    st.markdown(f"🔗 [Reference Documentation]({f.reference_url})")


def _render_inline_recommendations(findings):
    """Legacy stub — recommendations are now shown inline per finding row."""
    pass


# ----------------------------------------------------------------------
# Sidebar - upload + navigation
# ----------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ XC Security Reports")
    st.caption("F5 Distributed Cloud Security Auditor")

    uploaded = st.file_uploader("Upload Security Auditor JSON", type=["json"])
    if uploaded is not None and uploaded.name != st.session_state.source_name:
        _load_file(uploaded)

    if st.session_state.summary is not None:
        st.success(f"Loaded: {st.session_state.source_name}")
        st.divider()
        page = st.radio(
            "View",
            ["Dashboard", "Namespace Report", "Load Balancer Report"],
            label_visibility="collapsed",
        )
        st.divider()
        with st.expander("🧾 Customer Entitlements", expanded=False):
            st.caption(
                "Uncheck any product this customer hasn't purchased. "
                "Findings for unchecked products move to a separate "
                "'Not Purchased' section instead of showing as failures."
            )
            for product in PRODUCTS:
                st.session_state.entitlements[product.id] = st.checkbox(
                    product.label,
                    value=st.session_state.entitlements.get(product.id, True),
                    key=f"entitlement_{product.id}",
                )
        st.divider()
        st.session_state.show_timestamp = st.toggle(
            "Show timestamp in report",
            value=st.session_state.show_timestamp,
            key="toggle_timestamp",
        )
        st.session_state.show_trusted_clients = st.toggle(
            "Include Trusted Clients findings",
            value=st.session_state.show_trusted_clients,
            key="toggle_trusted_clients",
            help="Show Trusted Clients WAF, IP Reputation, and Threat Intel findings per LB",
        )
    else:
        page = None
        st.info("Upload a Security Auditor JSON export to get started.")

# ----------------------------------------------------------------------
# No data yet
# ----------------------------------------------------------------------
if st.session_state.summary is None:
    st.title("XC Security Report Generator")
    st.write(
        "Converts a raw F5 XC Security Auditor JSON export into readable, "
        "shareable Security Posture Review reports — a dashboard, a "
        "namespace-wide report, and per-Load-Balancer reports you can "
        "download as HTML."
    )
    st.write("Upload a JSON file in the sidebar to begin.")
    st.stop()

summary = st.session_state.summary
reports = st.session_state.reports
ns = st.session_state.namespace_report
all_findings = st.session_state.all_findings
entitlements = st.session_state.entitlements

any_unpurchased = any(not v for v in entitlements.values())

# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------
if page == "Dashboard":
    st.title(f"Dashboard — {summary.tenant} / {summary.namespace}")
    st.caption(f"Scan timestamp: {summary.timestamp}")

    if any_unpurchased:
        view_mode = st.radio(
            "Recommendation view",
            ["All Recommendations", "Purchased Products Only"],
            horizontal=True,
            help=(
                "'Purchased Products Only' excludes findings for products the "
                "customer hasn't bought (set in the sidebar) from the counts "
                "below, so the dashboard doesn't show 'critical' failures for "
                "features they never had access to."
            ),
        )
    else:
        view_mode = "All Recommendations"

    if view_mode == "Purchased Products Only":
        ns_summary = rd.namespace_summary_entitled(summary, reports, all_findings, entitlements)
    else:
        ns_summary = rd.namespace_summary(summary, reports)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Security Score", f"{ns_summary['score']}/100")
    c2.metric("Load Balancers", ns_summary["load_balancers"])
    c3.metric("Critical", ns_summary["critical"])
    c4.metric("High", ns_summary["high"])
    c5.metric("Passed Checks", ns_summary["passed"])

    st.divider()

    col_chart, col_dl = st.columns([2, 1])

    with col_chart:
        st.subheader("Findings by Severity")
        chart_data = {
            "Critical": ns_summary["critical"],
            "High": ns_summary["high"],
            "Medium": ns_summary["medium"],
            "Low": ns_summary["low"],
        }
        st.bar_chart(chart_data)

    with col_dl:
        st.subheader("Downloads")
        ns_html = he.render_namespace_report(
            summary, reports, ns, checklist_answers=st.session_state.checklist_answers,
            entitlements=entitlements, all_findings=all_findings,
            edited_messages=st.session_state.edited_messages,
            policy_overrides=st.session_state.policy_overrides,
            waf_modes=st.session_state.waf_modes,
            show_timestamp=st.session_state.show_timestamp,
        )
        st.download_button(
            "⬇️ Namespace Report (HTML)",
            data=ns_html,
            file_name=f"namespace-report-{summary.namespace}.html",
            mime="text/html",
            use_container_width=True,
        )

    if any_unpurchased:
        st.divider()
        not_purchased_products = [p.label for p in PRODUCTS if not entitlements.get(p.id, True)]
        _, not_purchased = split_findings(all_findings, entitlements)
        not_purchased_open = [f for f in not_purchased if f.status.upper() != "PASS"]
        with st.expander(
            f"💡 Additional Opportunities ({len(not_purchased_open)})",
            expanded=False,
        ):
            st.caption(
                "Potential enhancements to further strengthen the security posture."
            )
            for f in not_purchased_open:
                st.write(f"- **{f.rule_name}** ({f.object_name}): {f.message}")

    st.divider()
    st.subheader(f"Load Balancers ({len(reports)})")

    search = st.text_input("Search load balancers", "")
    severity_filter = st.multiselect(
        "Filter by health", ["Critical", "Needs Attention", "Fair", "Healthy"], default=[]
    )

    if view_mode == "Purchased Products Only":
        rows = [rd.lb_summary_entitled(lb, entitlements, checklist_answers=st.session_state.checklist_answers) for lb in reports.values()]
    else:
        rows = [rd.lb_summary(lb, checklist_answers=st.session_state.checklist_answers) for lb in reports.values()]
    rows.sort(key=lambda r: r["name"].lower())

    if search:
        rows = [r for r in rows if search.lower() in r["name"].lower()]
    if severity_filter:
        rows = [r for r in rows if r["health"] in severity_filter]

    st.caption(f"Showing {len(rows)} of {len(reports)} load balancers")

    selected_names = []
    for r in rows:
        cols = st.columns([0.5, 3, 1.5, 1, 1, 1, 1.5])
        with cols[0]:
            checked = st.checkbox("", key=f"sel_{r['name']}")
            if checked:
                selected_names.append(r["name"])
        cols[1].write(f"**{r['name']}**")
        cols[2].write(f"{r['health_icon']} {r['health']}")
        cols[3].write(f"🔴 {r['critical']}")
        cols[4].write(f"🟠 {r['high']}")
        cols[5].write(f"✅ {r['passed']}")
        if cols[6].button("View report", key=f"view_{r['name']}"):
            st.session_state.selected_lb = r["name"]
            st.rerun()

    if selected_names:
        st.divider()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in selected_names:
                lb_html = he.render_lb_report(
                    summary, reports[name], entitlements=entitlements,
                    edited_messages=st.session_state.edited_messages,
                    policy_overrides=st.session_state.policy_overrides,
                    waf_mode=st.session_state.waf_modes.get(name),
                    checklist_answers=st.session_state.checklist_answers,
                    policy_classifications=st.session_state.policy_classifications.get(name),
                    show_timestamp=st.session_state.show_timestamp,
                    all_findings=all_findings,
                    show_trusted_clients=st.session_state.show_trusted_clients,
                    excluded_findings=st.session_state.excluded_findings,
                )
                zf.writestr(f"{name}.html", lb_html)
        st.download_button(
            f"⬇️ Download {len(selected_names)} selected report(s) as ZIP",
            data=buf.getvalue(),
            file_name=f"lb-reports-{summary.namespace}.zip",
            mime="application/zip",
        )
        try:
            guide_bytes = docx_export.render_best_practice_docx(
                summary, [reports[n] for n in selected_names], all_findings,
                manual_items=MANUAL_CHECKLIST_ITEMS,
                edited_messages=st.session_state.edited_messages,
                excluded_findings=st.session_state.excluded_findings,
            )
            st.download_button(
                f"📝 Download Best Practice Guide (Word) — {len(selected_names)} LB(s)",
                data=guide_bytes,
                file_name=f"best-practice-guide-{summary.namespace}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        except Exception as e:
            st.error(f"Word guide generation failed: {e}")

# ----------------------------------------------------------------------
# Namespace Report
# ----------------------------------------------------------------------
elif page == "Namespace Report":
    st.title(f"Namespace Report — {summary.namespace}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Tenant-wide findings", len(ns.tenant_findings))
    c2.metric("WAF findings (tenant-wide)", len(ns.waf_policy_findings))
    c3.metric("Orphaned resources", len(ns.orphan_service_policy_findings) + len(ns.orphan_origin_pool_findings))

    ns_html = he.render_namespace_report(
            summary, reports, ns, checklist_answers=st.session_state.checklist_answers,
            entitlements=entitlements, all_findings=all_findings,
            edited_messages=st.session_state.edited_messages,
            policy_overrides=st.session_state.policy_overrides,
            waf_modes=st.session_state.waf_modes,
            show_timestamp=st.session_state.show_timestamp,
        )
    st.download_button(
        "⬇️ Download Namespace Report (HTML)",
        data=ns_html,
        file_name=f"namespace-report-{summary.namespace}.html",
        mime="text/html",
    )

    st.divider()

    with st.expander(f"Tenant-Wide Findings ({len(ns.tenant_findings)})", expanded=True):
        render_editable_findings_table(ns.tenant_findings, key_prefix="ns_tenant", show_object=False)

    with st.expander(f"WAF Policy Findings — tenant-wide ({len(ns.waf_policy_findings)})"):
        st.info(
            "The Security Auditor doesn't identify which WAF policy or Load "
            "Balancer these findings belong to (objectName is always "
            "\"unknown\" in the source JSON), so they're shown here instead "
            "of attached to a specific LB."
        )
        render_editable_findings_table(ns.waf_policy_findings, key_prefix="ns_waf", show_object=False)

    with st.expander("WAF Enforcement Mode — per LB (manual entries)"):
        set_modes = {k: v for k, v in st.session_state.waf_modes.items() if v and v != "Not Set"}
        if set_modes:
            st.table(pd.DataFrame(
                [{"Load Balancer": k, "Mode": v} for k, v in sorted(set_modes.items())]
            ))
        else:
            st.caption("Not set yet — fill in WAF Enforcement Mode from each LB's report page.")

    with st.expander(f"Unassigned Service Policies ({len(ns.orphan_service_policy_findings)})"):
        st.caption("Service policies not referenced by any Load Balancer's findings.")
        st.info(
            "ℹ️ 'Likely N/A (heuristic)' is a naming-convention guess at the policy's real purpose, "
            "not a certainty — override it in the Applicability column if wrong."
        )
        render_editable_findings_table(
            ns.orphan_service_policy_findings, key_prefix="ns_orphan_sp", show_object=True, show_applicability=True,
        )

    with st.expander(f"Unmatched Origin Pools ({len(ns.orphan_origin_pool_findings)})"):
        st.caption("Origin pools whose name didn't heuristically match any Load Balancer name.")
        render_editable_findings_table(ns.orphan_origin_pool_findings, key_prefix="ns_orphan_op", show_object=True)

    with st.expander(f"Logging & Alerting ({len(ns.log_receiver_findings) + len(ns.alert_policy_findings) + len(ns.alert_receiver_findings)})"):
        render_editable_findings_table(
            ns.log_receiver_findings + ns.alert_policy_findings + ns.alert_receiver_findings,
            key_prefix="ns_logging", show_object=True,
        )

    st.divider()
    st.subheader("Manual Review Checklist")
    st.caption(
        "These items aren't detectable from the Security Auditor export "
        "(console/tenant-level operational practices). Fill them in by hand — "
        "your answers are included in the downloaded HTML report."
    )
    answers = st.session_state.checklist_answers
    for item in MANUAL_CHECKLIST_ITEMS:
        col1, col2 = st.columns([1, 3])
        current = answers.get(item.id, {"status": "Not Reviewed", "notes": ""})
        with col1:
            status = st.selectbox(
                item.label,
                STATUS_OPTIONS,
                index=STATUS_OPTIONS.index(current["status"]),
                key=f"chk_status_{item.id}",
                label_visibility="collapsed",
            )
        with col2:
            st.write(f"**{item.label}**")
            st.caption(item.guidance)
            notes = st.text_input(
                "Notes", value=current["notes"], key=f"chk_notes_{item.id}",
                label_visibility="collapsed", placeholder="Optional notes...",
            )
            if status in ("No", "N/A") and item.recommendation:
                st.info(f"**Recommendation:** {item.recommendation}" + (f"\n\n[Reference]({item.reference_url})" if item.reference_url else ""))
        answers[item.id] = {"status": status, "notes": notes}
    st.session_state.checklist_answers = answers
    # Apply TLS blindfolded checklist answer to CERT-02 findings
    apply_tls_blindfolded(all_findings, st.session_state.checklist_answers)

# ----------------------------------------------------------------------
# Load Balancer Report
# ----------------------------------------------------------------------
elif page == "Load Balancer Report":
    st.title("Load Balancer Report")
    # Apply TLS blindfolded answer to CERT-02 findings
    apply_tls_blindfolded(all_findings, st.session_state.checklist_answers)

    lb_names = sorted(reports.keys(), key=str.lower)
    default_index = 0
    if st.session_state.get("selected_lb") in lb_names:
        default_index = lb_names.index(st.session_state.selected_lb)

    chosen = st.selectbox("Select a load balancer", lb_names, index=default_index)
    lb = reports[chosen]

    lb_view_mode = "All Recommendations"
    if any_unpurchased:
        lb_view_mode = st.radio(
            "Recommendation view",
            ["All Recommendations", "Purchased Products Only"],
            horizontal=True,
            key="lb_view_mode",
        )

    lb_findings_all = rd.lb_all_findings(lb)
    lb_findings_shown, lb_findings_not_purchased = split_findings(lb_findings_all, entitlements)
    checklist = st.session_state.checklist_answers
    if lb_view_mode == "Purchased Products Only":
        s = rd.lb_summary_entitled(lb, entitlements, checklist_answers=checklist)
        display_findings = lb_findings_shown
    else:
        s = rd.lb_summary(lb, checklist_answers=checklist, not_purchased_findings=lb_findings_not_purchased)
        display_findings = lb_findings_all
    # --- Standalone tab rules: findings that appear in their own dedicated sections ---
    _STANDALONE_TAB_RULES = {
        "TLS-01", "TLS-02", "TLS-03", "TLS-04", "TLS-05", "TLS-06",  # TLS
        "CERT-01", "CERT-02", "CERT-03",  # Certificates
        "OP-01", "OP-02", "OP-03", "OP-04", "OP-05", "OP-06", "OP-07", "OP-08", "OP-09", "OP-10",  # Origin Pool
        "HC-01",                      # Health Check
        "WAF-01", "WAF-02", "WAF-03", "WAF-04", "WAF-05",  # WAF Configuration
        "WAFP-01", "WAFP-02", "WAFP-03", "WAFP-04", "WAFP-05", "WAFP-06", "WAFP-07", "WAFP-REF",  # WAF Policy
        "BOT-01", "BOT-02", "BOT-03", "BOT-04",  # Bot Defense + MUD
        "API-01", "API-02", "API-03", "API-04", "API-05", "API-06", "API-07",  # API Protection
        "DDOS-01", "DDOS-02", "DDOS-03",  # DDoS
        "CSD-01", "CSD-02",          # Client-Side Defense
        "SP-01", "SP-02", "AC-01",    # Service Policy
        "AC-03", "AC-04", "AC-05", "AC-06",  # Access Control (Service Policy related)
        "RL-01", "RL-02",            # Rate Limiting
        "AC-02",                      # IP Reputation
    }
    # Informational rules (INFO/SKIP only, no standalone tab)
    _INFORMATIONAL_RULES = {"EXP-01", "EXP-02"}

    # Severity tabs: FAIL/WARN from ALL findings (including standalone tab rules)
    all_severity_findings = [f for f in display_findings if f.status.upper() in ("FAIL", "WARN", "ERROR")]
    grouped = rd.group_findings_by_severity(all_severity_findings)

    # Baseline Compliance: PASS findings NOT in standalone tabs and NOT informational
    baseline_findings = [f for f in display_findings
                         if f.status.upper() == "PASS"
                         and f.rule_id not in _STANDALONE_TAB_RULES
                         and f.rule_id not in _INFORMATIONAL_RULES]

    # Informational findings tab
    informational_findings = [f for f in display_findings if f.rule_id in _INFORMATIONAL_RULES]

    col_h, col_dl = st.columns([3, 1])
    with col_h:
        _health_badge(s["health"], s["health_icon"])
        st.caption(f"WAF policy: {s['waf_policy_name']} ({'assigned' if s['waf_assigned'] else 'not assigned'})")
        # v2: WAF mode comes from WAFP-01 finding
        waf_mode = lb.waf_mode or "Not Set"
        st.caption(f"WAF Enforcement Mode: {waf_mode}")
        st.session_state.waf_modes[lb.name] = waf_mode
    with col_dl:
        # Build tenant context for HTML export (without WAF exclusion - now auto-detected)
        tenant_ctx = {
            "summary_lines": [
                ("Alert Policies Active", any(f.status.upper() == "PASS" for f in ns.alert_policy_findings) if ns and ns.alert_policy_findings else False),
                ("SIEM / Global Log Receiver Configured", any(f.status.upper() == "PASS" for f in ns.log_receiver_findings) if ns and ns.log_receiver_findings else False),
            ] + [
                (item.label, st.session_state.checklist_answers.get(item.id, {}).get("status", "Not Reviewed"))
                for item in MANUAL_CHECKLIST_ITEMS
                if item.id != "tls-blindfolded"
            ],
        }
        # WAF exclusion auto-detected from namespace-level service policy findings
        has_waf_excl, waf_excl_policies = pt.has_waf_exclusion_policies(lb.name, all_findings)
        tenant_ctx["waf_exclusion_detected"] = has_waf_excl
        tenant_ctx["waf_exclusion_policies"] = waf_excl_policies
        tenant_ctx["waf_exclusion_notes"] = st.session_state.get(f"waf_excl_notes_{lb.name}", "")

        lb_html = he.render_lb_report(
            summary, lb, entitlements=entitlements,
            edited_messages=st.session_state.edited_messages,
            policy_overrides=st.session_state.policy_overrides,
            waf_mode=waf_mode if waf_mode != "Not Set" else None,
            tenant_context=tenant_ctx,
            checklist_answers=st.session_state.checklist_answers,
            policy_classifications=st.session_state.policy_classifications.get(lb.name),
            show_timestamp=st.session_state.show_timestamp,
            all_findings=all_findings,
            show_trusted_clients=st.session_state.show_trusted_clients,
            excluded_findings=st.session_state.excluded_findings,
        )
        st.download_button(
            "⬇️ Download Report (HTML)",
            data=lb_html,
            file_name=f"{lb.name}.html",
            mime="text/html",
            use_container_width=True,
        )
        try:
            pdf_bytes = pdf_export.render_lb_pdf(lb_html)
            st.download_button(
                "📄 Download Report (PDF)",
                data=pdf_bytes,
                file_name=f"{lb.name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation failed: {e}")
        try:
            docx_bytes = docx_export.render_best_practice_docx(
                summary, [lb], all_findings,
                manual_items=MANUAL_CHECKLIST_ITEMS,
                edited_messages=st.session_state.edited_messages,
                excluded_findings=st.session_state.excluded_findings,
            )
            st.download_button(
                "📝 Download Best Practice Guide (Word)",
                data=docx_bytes,
                file_name=f"{lb.name}-best-practice-guide.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"Word guide generation failed: {e}")

    # Adjust summary metrics for excluded findings
    # We must deduplicate because the same key can appear in multiple sub-lists
    excluded = st.session_state.excluded_findings
    if excluded:
        already_subtracted = set()
        for f in lb_findings_all:
            fkey = f"{f.rule_id}::{f.object_name}"
            if fkey in excluded and fkey not in already_subtracted:
                already_subtracted.add(fkey)
                status = f.status.upper()
                if status == "PASS":
                    s["passed"] -= 1
                elif status in ("FAIL", "WARN", "ERROR"):
                    sev = (f.severity or "").upper()
                    for k in ("critical", "high", "medium", "low"):
                        if sev == k.upper():
                            s[k] -= 1
                            break
                elif status in ("INFO", "SKIP"):
                    s["informational"] -= 1
                s["total"] -= 1

    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
    c1.metric("Critical", s["critical"])
    c2.metric("High", s["high"])
    c3.metric("Medium", s["medium"])
    c4.metric("Low", s["low"])
    c5.metric("Passed", s["passed"])
    c6.metric("Informational", s["informational"])
    c7.metric("Total Assessed", s["total"])

    not_purchased_open = [f for f in lb_findings_not_purchased if f.status.upper() != "PASS"]
    if not_purchased_open:
        with st.expander(f"💡 Additional Opportunities ({len(not_purchased_open)})"):
            st.caption("Potential enhancements to further strengthen the security posture.")
            for f in not_purchased_open:
                st.write(f"- **{f.rule_name}**: {f.message}")

    st.divider()
    st.caption("Message column is editable — edits are marked ✏️ here (internal only) and flow into the downloaded HTML report cleanly, without the marker.")

    # --- Extract findings for standalone tabs (v2 rule IDs) ---
    from product_entitlements import is_entitled

    # IP Reputation (AC-02)
    ip_rep_findings = [f for f in lb.lb_findings if f.rule_id == "AC-02" and is_entitled(f, entitlements)]
    ip_rep_sp = pt.filter_findings_by_category(
        lb.service_policy_findings, pt.IP_REPUTATION, lb.service_policy_names,
        st.session_state.policy_classifications.get(lb.name))

    # Client-Side Defense (CSD-01, CSD-02 — product-gated)
    csd_findings = [f for f in lb.lb_findings if f.rule_id in ("CSD-01", "CSD-02") and is_entitled(f, entitlements)]
    csd_sp = pt.filter_findings_by_category(
        lb.service_policy_findings, pt.CLIENT_SIDE_DEFENSE, lb.service_policy_names,
        st.session_state.policy_classifications.get(lb.name)) if csd_findings else []

    # Trusted Clients (optional)
    tc_waf = pt.get_trusted_clients_waf_findings(lb.name, all_findings) if st.session_state.show_trusted_clients else []
    tc_ip_rep = pt.get_trusted_clients_ip_rep_findings(lb.name, all_findings) if st.session_state.show_trusted_clients else []
    tc_threat_intel = pt.get_trusted_clients_threat_intel_findings(lb.name, all_findings) if st.session_state.show_trusted_clients else []

    # DDoS Protection (DDOS-01, DDOS-02, DDOS-03)
    ddos_findings = [f for f in lb.lb_findings if f.rule_id in ("DDOS-01", "DDOS-02", "DDOS-03")]

    # Bot Defense (BOT-01, BOT-04 — product-gated)
    bot_findings = [f for f in lb.lb_findings if f.rule_id in ("BOT-01", "BOT-04") and is_entitled(f, entitlements)]

    # Malicious User Detection (BOT-02, BOT-03 — product-gated)
    mud_findings = [f for f in lb.lb_findings if f.rule_id in ("BOT-02", "BOT-03") and is_entitled(f, entitlements)]

    # API Protection (only show standalone tab if product is purchased)
    api_prot_findings = [f for f in lb.lb_findings if f.rule_id.startswith("API-")] if entitlements.get("api_protection", True) else []

    # Rate Limiting (RL-01, RL-02 — product-gated)
    rate_limit_findings = [f for f in lb.lb_findings if f.rule_id in ("RL-01", "RL-02") and is_entitled(f, entitlements)]

    # Service policy classification
    lb_classifications = st.session_state.policy_classifications.get(lb.name, {})
    policy_groups = pt.group_policies_by_category(
        lb.service_policy_names, lb.service_policy_findings, lb_classifications)
    has_geo, geo_policies = pt.lb_geo_blocking_status(lb.service_policy_names, lb_classifications)
    has_http, http_policies = pt.lb_http_method_status(lb.service_policy_names, lb_classifications)

    # Filter service policy findings for the SP tab (exclude WAF exclusion, IP rep, CSD)
    sp_tab_categories = {pt.GEO_BLOCKING, pt.HTTP_METHOD, pt.ALLOW_ALL, pt.OTHER}
    sp_tab_policy_names = set()
    for cat in sp_tab_categories:
        sp_tab_policy_names.update(policy_groups.get(cat, []))
    sp_tab_findings = [f for f in lb.service_policy_findings if f.object_name in sp_tab_policy_names]

    # TLS findings (TLS-01 through TLS-06)
    tls_findings = [f for f in lb.lb_findings if f.rule_id.startswith("TLS-")]

    # Certificate findings
    cert_findings = lb.certificate_findings

    # Malware Detection (WAF-03)
    malware_findings = [f for f in lb.lb_findings if f.rule_id == "WAF-03"]

    # WAF exclusion auto-detect from namespace findings
    has_waf_excl, waf_excl_policies = pt.has_waf_exclusion_policies(lb.name, all_findings)

    tabs = st.tabs([
        "High", "Medium", "Low",
        "TLS", "Certificates", "Origin Pools", "Health Check",
        "WAF Configuration", "WAF Policy Details",
        "Bot Defense", "API Protection", "Malware Detection",
        "DDoS Protection", "Client-Side Defense",
        "Service Policies", "Rate Limiting", "IP Reputation",
        "Informational Findings", "Baseline Compliance",
        "Tenant-Wide Context", "Additional Opportunities",
    ])

    with tabs[0]:
        high = grouped.get("HIGH", [])
        st.caption(f"{len(high)} high findings")
        render_editable_findings_table(high, key_prefix=f"high_{lb.name}", show_object=True)
        _render_inline_recommendations(high)

    with tabs[1]:
        medium = grouped.get("MEDIUM", [])
        st.caption(f"{len(medium)} medium findings")
        render_editable_findings_table(medium, key_prefix=f"med_{lb.name}", show_object=True)
        _render_inline_recommendations(medium)

    with tabs[2]:
        low = grouped.get("LOW", [])
        st.caption(f"{len(low)} low findings")
        render_editable_findings_table(low, key_prefix=f"low_{lb.name}", show_object=True)
        _render_inline_recommendations(low)

    # --- TLS tab ---
    with tabs[3]:
        if tls_findings:
            render_editable_findings_table(tls_findings, key_prefix=f"tls_{lb.name}", show_object=True)
            _render_inline_recommendations(tls_findings)
        else:
            st.caption("No TLS findings for this load balancer.")

    # --- Certificates tab ---
    with tabs[4]:
        if cert_findings:
            render_editable_findings_table(cert_findings, key_prefix=f"cert_{lb.name}", show_object=True)
            _render_inline_recommendations(cert_findings)
        else:
            st.caption("No certificate findings for this load balancer.")

    # --- Origin Pools tab ---
    with tabs[5]:
        if lb.origin_findings:
            render_editable_findings_table(lb.origin_findings, key_prefix=f"origin_{lb.name}", show_object=True)
            _render_inline_recommendations(lb.origin_findings)
        else:
            st.caption("No origin pool findings for this load balancer.")

    # --- Health Check tab ---
    with tabs[6]:
        if lb.health_check_findings:
            render_editable_findings_table(lb.health_check_findings, key_prefix=f"health_{lb.name}", show_object=True)
            _render_inline_recommendations(lb.health_check_findings)
        else:
            st.caption("No health check findings for this load balancer.")

    # --- WAF Configuration tab ---
    with tabs[7]:
        st.subheader("WAF Configuration")
        waf_name = lb.waf_policy_name or "None"
        st.write(f"- **WAF Policy Name:** {waf_name} ({'assigned' if lb.waf_assigned else 'not assigned'})")
        st.write(f"- **WAF Enforcement Mode:** {lb.waf_mode or 'Not Set'}")
        if lb.waf_mode and lb.waf_mode != "Blocking":
            from manual_checklist import WAF_MODE_RECOMMENDATION, WAF_MODE_REFERENCE_URL
            st.warning("**Recommendation:**\n\n" + WAF_MODE_RECOMMENDATION + f"\n\n[Reference]({WAF_MODE_REFERENCE_URL})")
        # WAF Config findings (WAF-01/02/04/05 — not WAF-03 which is Malware)
        waf_config_findings = [f for f in lb.lb_findings if f.rule_id in ("WAF-01", "WAF-02", "WAF-04", "WAF-05")]
        if waf_config_findings:
            st.divider()
            render_editable_findings_table(waf_config_findings, key_prefix=f"wafcfg_{lb.name}", show_object=True)
        # WAF Exclusion Rules (auto-detected or from WAF-02)
        _EXCL_ARTICLE_URL = "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-tos/advanced-security/manage-waf-exclusion-rules"
        waf_excl_finding = next((f for f in lb.lb_findings if f.rule_id == "WAF-02"), None)
        if waf_excl_finding:
            has_exclusions = "no waf exclusion" not in (waf_excl_finding.message or "").lower()
            if has_exclusions:
                st.warning(f"- **WAF Exclusion Rules:** {waf_excl_finding.message}\n\n[WAF Exclusion Rules Reference ↗]({_EXCL_ARTICLE_URL})")
            else:
                st.write("- **WAF Exclusion Rules:** None detected")
        elif has_waf_excl:
            st.success(f"WAF Exclusion Rules detected via service policies: {', '.join(waf_excl_policies)}")
            from manual_checklist import WAF_EXCLUSION_RECOMMENDATION, WAF_EXCLUSION_REFERENCE_URL
            st.info(f"**Review Recommendation:** {WAF_EXCLUSION_RECOMMENDATION}\n\n[Reference]({WAF_EXCLUSION_REFERENCE_URL})")
        else:
            st.write("- **WAF Exclusion Rules:** None detected")
        # Notes input for WAF exclusion details
        waf_excl_notes_key = f"waf_excl_notes_{lb.name}"
        if waf_excl_notes_key not in st.session_state:
            st.session_state[waf_excl_notes_key] = ""
        waf_excl_notes = st.text_area(
            "WAF Exclusion Notes (optional — flows into HTML report)",
            value=st.session_state[waf_excl_notes_key],
            key=f"waf_excl_notes_input_{lb.name}",
            placeholder="e.g., 3 exclusion rules reviewed — all scoped to specific URIs, no overly broad rules found.",
            height=80,
        )
        st.session_state[waf_excl_notes_key] = waf_excl_notes
        if tc_waf:
            st.divider()
            st.subheader(f"Trusted Clients — WAF ({len(tc_waf)})")
            render_editable_findings_table(tc_waf, key_prefix=f"tc_waf_{lb.name}", show_object=True)

    # --- WAF Policy Details tab ---
    with tabs[8]:
        if lb.waf_policy_findings:
            render_editable_findings_table(lb.waf_policy_findings, key_prefix=f"wafp_{lb.name}", show_object=True)
            _render_inline_recommendations(lb.waf_policy_findings)
        else:
            st.caption("No WAF Policy findings for this LB.")

    # --- Bot Defense tab ---
    with tabs[9]:
        if bot_findings:
            render_editable_findings_table(bot_findings, key_prefix=f"bot_{lb.name}", show_object=False)
            _render_inline_recommendations(bot_findings)
        else:
            st.caption("No Bot Defense findings for this LB.")

    # --- API Protection tab ---
    with tabs[10]:
        if api_prot_findings:
            render_editable_findings_table(api_prot_findings, key_prefix=f"apiprot_{lb.name}", show_object=False)
            _render_inline_recommendations(api_prot_findings)
        else:
            st.caption("No API Protection findings for this LB.")

    # --- Malware Detection tab (WAF-03) ---
    with tabs[11]:
        if malware_findings:
            render_editable_findings_table(malware_findings, key_prefix=f"malware_{lb.name}", show_object=False)
            _render_inline_recommendations(malware_findings)
        else:
            st.caption("No Malware Detection findings for this LB.")
        if mud_findings:
            st.divider()
            st.subheader("Malicious User Detection (BOT-02/03)")
            render_editable_findings_table(mud_findings, key_prefix=f"mud_{lb.name}", show_object=False)
            _render_inline_recommendations(mud_findings)

    # --- DDoS Protection tab ---
    with tabs[12]:
        if ddos_findings:
            render_editable_findings_table(ddos_findings, key_prefix=f"ddos_{lb.name}", show_object=False)
            _render_inline_recommendations(ddos_findings)
        else:
            st.caption("No DDoS findings for this LB.")
        if tc_threat_intel:
            st.divider()
            st.subheader(f"Trusted Clients — Threat Intel ({len(tc_threat_intel)})")
            render_editable_findings_table(tc_threat_intel, key_prefix=f"tc_ti_{lb.name}", show_object=True)

    # --- Client-Side Defense tab ---
    with tabs[13]:
        if csd_findings:
            render_editable_findings_table(csd_findings, key_prefix=f"csd_{lb.name}", show_object=False)
            _render_inline_recommendations(csd_findings)
        else:
            st.caption("No Client-Side Defense findings for this LB.")
        if csd_sp:
            st.divider()
            st.subheader(f"CSD Service Policies ({len(csd_sp)})")
            render_editable_findings_table(csd_sp, key_prefix=f"csd_sp_{lb.name}", show_object=True)

    # --- Service Policies tab ---
    with tabs[14]:
        if lb.service_policy_names:
            st.caption(f"Assigned policies: {', '.join(lb.service_policy_names)}")

            # Service policy classification UI
            st.subheader("Policy Classification")
            st.caption("Classify each service policy. Auto-detected from naming conventions — override if needed.")
            if lb.name not in st.session_state.policy_classifications:
                st.session_state.policy_classifications[lb.name] = {}

            for sp_name in lb.service_policy_names:
                auto_cat = pt.auto_classify(sp_name)
                current_cat = st.session_state.policy_classifications[lb.name].get(sp_name, auto_cat)
                idx = pt.CLASSIFICATION_OPTIONS.index(current_cat) if current_cat in pt.CLASSIFICATION_OPTIONS else len(pt.CLASSIFICATION_OPTIONS) - 1
                chosen_cat = st.selectbox(
                    sp_name, pt.CLASSIFICATION_OPTIONS, index=idx,
                    key=f"sp_class_{lb.name}_{sp_name}",
                )
                if chosen_cat != auto_cat:
                    st.session_state.policy_classifications[lb.name][sp_name] = chosen_cat
                elif sp_name in st.session_state.policy_classifications[lb.name]:
                    del st.session_state.policy_classifications[lb.name][sp_name]

            st.divider()

            # Geo Blocking rollup
            st.subheader("Geo Blocking")
            if has_geo:
                st.success(f"✅ Geo blocking configured via: {', '.join(geo_policies)}")
            else:
                st.warning("⚠️ No geo-blocking policy detected for this LB.")
                st.info("**Recommendation:** Configure a geo-blocking service policy to restrict traffic from countries or regions that are not expected to access this application. This reduces the attack surface and blocks traffic from high-risk geographies.\n\n[Reference](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection)")

            # HTTP Method Restriction rollup
            st.subheader("HTTP Method Restriction")
            if has_http:
                st.success(f"✅ HTTP method restriction configured via: {', '.join(http_policies)}")
            else:
                st.warning("⚠️ No HTTP method restriction policy detected for this LB.")
                st.info("**Recommendation:** Configure a service policy to restrict allowed HTTP methods (e.g., permit only GET, POST, HEAD) and block unnecessary or dangerous methods (e.g., PUT, DELETE, TRACE, OPTIONS). This limits the attack surface and prevents method-based exploitation.\n\n[Reference](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection)")

            # Other policies
            other_policies = policy_groups.get(pt.OTHER, []) + policy_groups.get(pt.ALLOW_ALL, [])
            if other_policies:
                st.subheader(f"Other Policies ({len(other_policies)})")
                for p in other_policies:
                    st.write(f"- {p}")

            # Show raw findings for these categories if any
            if sp_tab_findings:
                st.divider()
                st.subheader(f"Service Policy Findings ({len(sp_tab_findings)})")
                render_editable_findings_table(
                    sp_tab_findings, key_prefix=f"sp_{lb.name}", show_object=True, show_applicability=True,
                )

            # Access Control findings (AC-01/03/04/05/06)
            ac_findings = [f for f in lb.lb_findings if f.rule_id in ("AC-01", "AC-03", "AC-04", "AC-05", "AC-06")]
            if ac_findings:
                st.divider()
                st.subheader(f"Access Control Findings ({len(ac_findings)})")
                render_editable_findings_table(ac_findings, key_prefix=f"ac_{lb.name}", show_object=True)
        else:
            st.caption("No service policies linked to this load balancer.")

    # --- Rate Limiting tab ---
    with tabs[15]:
        if rate_limit_findings:
            render_editable_findings_table(rate_limit_findings, key_prefix=f"ratelim_{lb.name}", show_object=False)
            _render_inline_recommendations(rate_limit_findings)
        else:
            st.caption("No Rate Limiting findings for this LB.")

    # --- IP Reputation tab ---
    with tabs[16]:
        if ip_rep_findings:
            render_editable_findings_table(ip_rep_findings, key_prefix=f"iprep_{lb.name}", show_object=False)
            _render_inline_recommendations(ip_rep_findings)
        else:
            st.caption("No IP Reputation findings for this LB.")
        if ip_rep_sp:
            st.divider()
            st.subheader(f"IP Reputation Service Policies ({len(ip_rep_sp)})")
            render_editable_findings_table(ip_rep_sp, key_prefix=f"iprep_sp_{lb.name}", show_object=True)
        if tc_ip_rep:
            st.divider()
            st.subheader(f"Trusted Clients — IP Reputation ({len(tc_ip_rep)})")
            render_editable_findings_table(tc_ip_rep, key_prefix=f"tc_iprep_{lb.name}", show_object=True)

    # --- Informational Findings tab ---
    with tabs[17]:
        if informational_findings:
            st.caption(f"{len(informational_findings)} informational findings")
            render_editable_findings_table(informational_findings, key_prefix=f"info_{lb.name}", show_object=True)
        else:
            st.caption("No informational findings.")

    # --- Baseline Compliance tab ---
    with tabs[18]:
        if baseline_findings:
            st.caption(f"{len(baseline_findings)} verified compliant checks")
            render_editable_findings_table(baseline_findings, key_prefix=f"baseline_{lb.name}", show_object=True)
        else:
            st.caption("No baseline compliance findings.")

    # --- Tenant-Wide Context tab ---
    with tabs[19]:
        st.caption("Not specific to this Load Balancer - see the Namespace Report to edit these.")
        # Auto-detected items (check finding STATUS, not just existence)
        alert_active = any(f.status.upper() == "PASS" for f in ns.alert_policy_findings) if ns and ns.alert_policy_findings else False
        glr_active = any(f.status.upper() == "PASS" for f in ns.log_receiver_findings) if ns and ns.log_receiver_findings else False
        st.write(f"- **Alert Policies Active:** {alert_active}")
        if not alert_active:
            st.info("**Recommendation:** Configure alert policies to receive notifications for security events and operational issues.\n\n[Reference](https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms)")
        st.write(f"- **SIEM / Global Log Receiver Configured:** {glr_active}")
        if not glr_active:
            st.info("**Recommendation:** Configure a Global Log Receiver to forward security logs to your SIEM for centralized monitoring, correlation, and incident response.\n\n[Reference](https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms)")
        # Manual checklist items (excluding TLS blindfolded — mapped to CERT-02)
        for item in MANUAL_CHECKLIST_ITEMS:
            if item.id == "tls-blindfolded":
                continue
            answer = st.session_state.checklist_answers.get(item.id, {"status": "Not Reviewed", "notes": ""})
            st.write(f"- **{item.label}:** {answer['status']}" + (f" — _{answer['notes']}_" if answer["notes"] else ""))
            if answer["status"] in ("No", "Not Reviewed") and item.recommendation:
                st.info(f"**Recommendation:** {item.recommendation}" + (f"\n\n[Reference]({item.reference_url})" if item.reference_url else ""))

    # --- Additional Opportunities tab ---
    with tabs[20]:
        not_purchased_open_tab = [f for f in lb_findings_not_purchased if f.status.upper() != "PASS"]
        if not_purchased_open_tab:
            st.caption("Potential enhancements to further strengthen the security posture.")
            for f in not_purchased_open_tab:
                st.write(f"- **{f.rule_name}**: {f.message}")
        else:
            st.caption("No additional opportunities to show.")
