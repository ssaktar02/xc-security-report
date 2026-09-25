"""
Renders self-contained, styled HTML reports (no external assets) for
download - a single Load Balancer, a Namespace report, or a combined
multi-LB bundle. Kept dependency-free (plain f-strings + html.escape)
so exports don't rely on a templates/ directory anyone can break.
"""

import html
from datetime import datetime

import report_data as rd

F5_RED = "#e2231a"
DARK = "#1a1a2e"


def _e(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _finding_key(f) -> str:
    return f"{f.rule_id}::{f.object_name}"


def _base_css() -> str:
    return f"""
    <style>
      * {{ box-sizing: border-box; }}
      body {{
        font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #222; background: #f5f6fa; margin: 0; padding: 0 0 60px 0;
        line-height: 1.5;
      }}
      .header {{
        background: linear-gradient(135deg, {DARK} 0%, #16213e 100%);
        color: white; padding: 32px 40px;
        border-bottom: 4px solid {F5_RED};
      }}
      .header h1 {{ margin: 0 0 6px 0; font-size: 24px; font-weight: 700; letter-spacing: -0.3px; }}
      .header .sub {{ opacity: 0.8; font-size: 13px; }}
      .container {{ max-width: 1020px; margin: 0 auto; padding: 28px 24px; }}
      .card {{
        background: white; border-radius: 10px; padding: 22px 26px;
        margin-bottom: 22px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        border: 1px solid #eaedf3;
      }}
      .card h2 {{
        margin-top: 0; font-size: 16px; font-weight: 600;
        border-bottom: 2px solid #f0f1f5; padding-bottom: 10px;
        color: #333; letter-spacing: -0.2px;
      }}
      .card h3 {{ font-size: 14px; font-weight: 600; color: #444; margin: 16px 0 8px 0; }}
      .stat-grid {{ display: flex; flex-wrap: wrap; gap: 10px; }}
      .stat {{
        flex: 1; min-width: 100px; text-align: center; padding: 16px 8px;
        border-radius: 8px; background: #f8f9fc; border: 1px solid #e8eaf0;
        transition: box-shadow 0.15s;
      }}
      .stat:hover {{ box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
      .stat .n {{ font-size: 26px; font-weight: 800; color: #222; }}
      .stat .l {{ font-size: 10px; text-transform: uppercase; color: #888; letter-spacing: 0.5px; margin-top: 2px; }}
      table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
      th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #f0f1f5; vertical-align: top; }}
      th {{ background: #f8f9fc; font-size: 11px; text-transform: uppercase; color: #777; font-weight: 600; letter-spacing: 0.3px; }}
      tr:hover {{ background: #fafbfe; }}
      .badge {{
        display: inline-block; padding: 3px 10px; border-radius: 20px;
        font-size: 10px; font-weight: 700; color: white; letter-spacing: 0.3px;
        text-transform: uppercase;
      }}
      .heuristic-note {{
        background: #fff8e1; border: 1px solid #f0d878; border-radius: 6px;
        padding: 8px 12px; font-size: 12px; color: #6b5900; margin-bottom: 10px;
      }}
      .muted {{ color: #888; font-size: 12px; }}
      .score {{ font-size: 38px; font-weight: 800; letter-spacing: -1px; }}
      .rec-box {{
        margin-top: 12px; padding: 12px 16px; border-radius: 8px;
        font-size: 12px; line-height: 1.6;
      }}
      .rec-box-warn {{ background: #fff3f3; border: 1px solid #fdd; }}
      .rec-box-info {{ background: #fff8e1; border: 1px solid #f0d878; }}
      a {{ color: #2563eb; text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .chevron-cell {{
        width: 28px; text-align: center; cursor: pointer; user-select: none;
        font-size: 14px; color: #555; padding: 10px 4px !important;
      }}
      .chevron-open, .chevron-closed {{
        display: inline-block; transition: transform 0.2s ease;
      }}
      .chevron-open {{ transform: rotate(90deg); }}
      .chevron-closed {{ transform: rotate(0deg); }}
      .finding-row {{ cursor: pointer; }}
      .finding-row:hover {{ background: #f0f4ff !important; }}
      .rec-row td {{ background: #fafbfe; }}
      .footer {{
        text-align: center; padding: 20px; font-size: 11px; color: #aaa;
        border-top: 1px solid #eee; margin-top: 40px;
      }}
      @media print {{
        body {{ background: white; }}
        .card {{ box-shadow: none; border: 1px solid #ddd; page-break-inside: avoid; }}
        .header {{ background: {DARK} !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        .badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        .stat {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        tr:hover {{ background: transparent; }}
      }}
    </style>
    <script>
    function toggleRec(row) {{
      var rec = row.nextElementSibling;
      if (!rec || !rec.classList.contains('rec-row')) return;
      var chevron = row.querySelector('.chevron-open, .chevron-closed');
      if (rec.style.display === 'none') {{
        rec.style.display = '';
        if (chevron) {{ chevron.className = 'chevron-open'; }}
      }} else {{
        rec.style.display = 'none';
        if (chevron) {{ chevron.className = 'chevron-closed'; }}
      }}
    }}
    function toggleTenantRec(el) {{
      var container = el.closest('td').nextElementSibling || el.closest('tr').querySelector('.rec-row-inline');
      if (!container) {{
        // Find the rec-row-inline div inside the same row
        var row = el.closest('tr');
        container = row.querySelector('.rec-row-inline');
      }}
      if (!container) return;
      if (container.style.display === 'none') {{
        container.style.display = '';
        el.className = 'chevron-open';
      }} else {{
        container.style.display = 'none';
        el.className = 'chevron-closed';
      }}
    }}
    </script>
    """


def _status_badge(status: str, severity: str) -> str:
    color = rd.status_badge_color(status, severity)
    return f'<span class="badge" style="background:{color}">{_e(rd.status_display_label(status))}</span>'


def _applicability_badge() -> str:
    return '<span class="badge" style="background:#bbbbbb;color:#333;">LIKELY N/A</span>'


def _stat_grid(items) -> str:
    cells = "".join(
        f'<div class="stat"><div class="n">{_e(v)}</div><div class="l">{_e(l)}</div></div>'
        for l, v in items
    )
    return f'<div class="stat-grid">{cells}</div>'


def _findings_table(findings, show_object=False, edited_messages=None, policy_overrides=None,
                     check_applicability=False) -> str:
    """Render findings as table rows with a chevron arrow (left of status) that
    expands a full-width recommendation row below each finding.
    FAIL/WARN/ERROR → expanded by default. PASS/INFO/SKIP → collapsed."""
    if not findings:
        return '<p class="muted">No findings in this category.</p>'

    edited_messages = edited_messages or {}
    rows = []
    for i, f in enumerate(findings):
        key = _finding_key(f)
        message = edited_messages.get(key, f.message)

        applicable = True
        if check_applicability:
            import policy_type
            appl = policy_type.applicability_with_override(f.object_name, f.rule_id, policy_overrides)
            applicable = appl.applicable

        status_html = _applicability_badge() if not applicable else _status_badge(f.status, f.severity)
        severity_html = f"<span class='muted'>{_e((f.severity or '').upper())}</span>"
        obj_col = f"<td>{_e(f.object_name)}</td>" if show_object else ""
        col_count = 5 + (1 if show_object else 0)

        row_style = ' style="opacity:0.6;"' if not applicable else ""
        status_upper = (f.status or "").upper()
        is_action = status_upper in ("FAIL", "WARN", "ERROR")

        # Arrow: ˅ (expanded) or › (collapsed)
        arrow_class = "chevron-open" if is_action else "chevron-closed"
        rec_display = "" if is_action else ' style="display:none;"'

        # Build recommendation content
        if is_action:
            rec_label = "Recommendation"
            rec_class = "rec-box rec-box-warn"
            rec_text = _e(f.remediation).replace("\\n", "<br>") if f.remediation else "Review this finding and take corrective action."
        else:
            rec_label = "Best Practice"
            rec_class = "rec-box rec-box-info"
            rec_text = _e(f.remediation).replace("\\n", "<br>") if f.remediation else "This check passed. No action required — continue monitoring."

        ref_html = ""
        if f.reference_url:
            ref_html = f' &nbsp;|&nbsp; <a href="{_e(f.reference_url)}" target="_blank">Reference Documentation ↗</a>'

        # Data row
        rows.append(
            f'<tr{row_style} class="finding-row" onclick="toggleRec(this)">'
            f'<td class="chevron-cell"><span class="{arrow_class}">&#x276F;</span></td>'
            f"<td>{status_html}</td>"
            f"<td>{severity_html}</td>"
            f"<td>{_e(f.rule_name)}<div class='muted'>{_e(f.rule_id)}</div></td>"
            f"{obj_col}"
            f"<td>{_e(message)}</td>"
            "</tr>"
        )
        # Recommendation row (full width)
        rows.append(
            f'<tr class="rec-row"{rec_display}>'
            f'<td colspan="{col_count}" style="padding:0 12px 12px 40px;border-bottom:1px solid #eaedf3;">'
            f'<div class="{rec_class}"><strong>{rec_label}:</strong> {rec_text}{ref_html}</div>'
            f"</td></tr>"
        )

    header_obj = "<th>Object</th>" if show_object else ""
    return f"""
    <table>
      <thead><tr><th style="width:28px;"></th><th>Status</th><th>Severity</th><th>Rule</th>{header_obj}<th>Message</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _inline_recommendations(findings) -> str:
    """Legacy stub — recommendations are now inline per finding row."""
    return ""


def _findings_table_opportunities(findings, edited_messages=None) -> str:
    """Additional Opportunities table: forces INFO badge, no Severity column."""
    if not findings:
        return '<p class="muted">No findings in this category.</p>'

    edited_messages = edited_messages or {}
    rows = []
    for f in findings:
        key = _finding_key(f)
        message = edited_messages.get(key, f.message)
        info_badge = f'<span class="badge" style="background:{rd.STATUS_COLORS["INFO"]}">INFO</span>'
        rows.append(
            f"<tr>"
            f"<td>{info_badge}</td>"
            f"<td>{_e(f.rule_name)}<div class='muted'>{_e(f.rule_id)}</div></td>"
            f"<td>{_e(message)}</td>"
            "</tr>"
        )

    return f"""
    <table>
      <thead><tr><th>Status</th><th>Rule</th><th>Message</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _findings_table_with_refs(findings, edited_messages=None) -> str:
    """Additional Opportunities table with reference links: INFO badge, no Severity column."""
    if not findings:
        return '<p class="muted">No findings in this category.</p>'

    edited_messages = edited_messages or {}
    rows = []
    for f in findings:
        key = _finding_key(f)
        message = edited_messages.get(key, f.message)
        info_badge = f'<span class="badge" style="background:{rd.STATUS_COLORS["INFO"]}">INFO</span>'
        ref_html = ""
        if f.reference_url:
            ref_html = f'<div class="muted"><a href="{_e(f.reference_url)}" target="_blank">Learn more</a></div>'
        rows.append(
            f"<tr>"
            f"<td>{info_badge}</td>"
            f"<td>{_e(f.rule_name)}<div class='muted'>{_e(f.rule_id)}</div></td>"
            f"<td>{_e(message)}{ref_html}</td>"
            "</tr>"
        )

    return f"""
    <table>
      <thead><tr><th>Status</th><th>Rule</th><th>Message</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _findings_table_opportunities_enhanced(findings, edited_messages=None) -> str:
    """Additional Opportunities table: enhanced styling with bold rule names."""
    if not findings:
        return '<p class="muted">No findings in this category.</p>'

    edited_messages = edited_messages or {}
    rows = []
    for f in findings:
        key = _finding_key(f)
        message = edited_messages.get(key, f.message)
        opp_badge = '<span class="badge" style="background:#e67e22;color:white;">OPPORTUNITY</span>'
        ref_html = ""
        if f.reference_url:
            ref_html = f'<div style="margin-top:4px;"><a href="{_e(f.reference_url)}" target="_blank" style="color:#2980b9;font-size:12px;">Learn more &rarr;</a></div>'
        rows.append(
            f"<tr>"
            f"<td>{opp_badge}</td>"
            f"<td><strong>{_e(f.rule_name)}</strong><div class='muted'>{_e(f.rule_id)}</div></td>"
            f"<td>{_e(message)}{ref_html}</td>"
            "</tr>"
        )

    return f"""
    <table>
      <thead><tr><th>Status</th><th>Rule</th><th>Message</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _recommendations_html(recs, checklist_answers=None) -> str:
    items = []
    for r in recs:
        remediation_html = _e(r["recommendation"]).replace("\n", "<br>")
        ref = f'<div class="muted"><a href="{_e(r["reference"])}" target="_blank">{_e(r["reference"])}</a></div>' if r.get("reference") else ""
        badge_color = rd.FAIL_SEVERITY_COLORS.get((r["severity"] or "").upper(), "#999")
        items.append(f"""
        <div style="padding:12px 0; border-bottom:1px solid #eee;">
          <div><span class="badge" style="background:{badge_color}">{_e((r['severity'] or '').upper())}</span>
            <strong>{_e(r['rule'])}</strong>
            <span class="muted">({_e(r['rule_id'])})</span></div>
          <div style="margin-top:6px; font-size:13px;">{remediation_html}</div>
          {ref}
        </div>
        """)

    # Manual checklist recommendations (when answered No or Not Reviewed)
    from manual_checklist import MANUAL_CHECKLIST_ITEMS
    manual_items = []
    for item in MANUAL_CHECKLIST_ITEMS:
        if item.id == "tls-blindfolded":
            continue
        answer = (checklist_answers or {}).get(item.id, {"status": "Not Reviewed"}).get("status", "Not Reviewed")
        if answer in ("No", "Not Reviewed") and item.recommendation:
            rec_text = _e(item.recommendation).replace("\n", "<br>")
            ref_html = f'<div class="muted"><a href="{_e(item.reference_url)}" target="_blank">{_e(item.reference_url)}</a></div>' if item.reference_url else ""
            badge_color = rd.FAIL_SEVERITY_COLORS.get("MEDIUM", "#e67e22")
            manual_items.append(f"""
            <div style="padding:12px 0; border-bottom:1px solid #eee;">
              <div><span class="badge" style="background:{badge_color}">MEDIUM</span>
                <strong>{_e(item.short_name or item.label)}</strong>
                <span class="muted">(Tenant-Wide Check)</span></div>
              <div style="margin-top:6px; font-size:13px;">{rec_text}</div>
              {ref_html}
            </div>
            """)

    if manual_items:
        items.extend(manual_items)

    if not items:
        return '<p class="muted">No open recommendations - nice work.</p>'

    return "".join(items)


def render_lb_report(summary, lb, generated_at=None, entitlements=None, edited_messages=None,
                      policy_overrides=None, waf_mode=None, tenant_context=None,
                      checklist_answers=None, policy_classifications=None,
                      show_timestamp=True, all_findings=None,
                      show_trusted_clients=False, excluded_findings=None) -> str:
    # Apply TLS blindfolded checklist answer to CERT-02 findings before rendering
    from finding_corrections import apply_tls_blindfolded
    apply_tls_blindfolded(lb.lb_findings, checklist_answers)

    _excluded = excluded_findings or set()

    all_lb_findings = [f for f in rd.lb_all_findings(lb) if _finding_key(f) not in _excluded]

    # Helper to filter exclusions from any finding list
    def _filter(flist):
        return [f for f in flist if _finding_key(f) not in _excluded]

    not_purchased_open = []
    if entitlements:
        from product_entitlements import split_findings
        shown_findings, not_purchased = split_findings(all_lb_findings, entitlements)
        not_purchased_open = [f for f in not_purchased if f.status.upper() != "PASS"]
        s = rd.lb_summary_entitled(lb, entitlements, checklist_answers=checklist_answers)
    else:
        shown_findings = all_lb_findings
        not_purchased_open = []
        s = rd.lb_summary(lb, checklist_answers=checklist_answers)

    # Adjust summary counts for excluded findings
    if _excluded:
        all_unfiltered = rd.lb_all_findings(lb)
        already_subtracted = set()
        for f in all_unfiltered:
            fkey = _finding_key(f)
            if fkey in _excluded and fkey not in already_subtracted:
                already_subtracted.add(fkey)
                st_upper = f.status.upper()
                if st_upper == "PASS":
                    s["passed"] -= 1
                elif st_upper in ("FAIL", "WARN", "ERROR"):
                    sev_upper = (f.severity or "").upper()
                    for k in ("critical", "high", "medium", "low"):
                        if sev_upper == k.upper():
                            s[k] -= 1
                            break
                elif st_upper in ("INFO", "SKIP"):
                    s["informational"] -= 1
                s["total"] -= 1

    # Filter out findings that have their own standalone sections
    _STANDALONE_RULES = {
        "TLS-01", "TLS-02", "TLS-03", "TLS-04", "TLS-05", "TLS-06",
        "CERT-01", "CERT-02", "CERT-03", "HC-01",
        "BOT-01", "BOT-02", "BOT-03", "BOT-04",
        "API-01", "API-02", "API-03", "API-04", "API-05", "API-06", "API-07",
        "DDOS-01", "DDOS-02", "DDOS-03", "CSD-01", "CSD-02", "AC-02",
        "RL-01", "RL-02", "WAF-01", "WAF-02", "WAF-03", "WAF-04", "WAF-05",
        "WAFP-01", "WAFP-02", "WAFP-03", "WAFP-04", "WAFP-05", "WAFP-06", "WAFP-07", "WAFP-REF",
        "SP-01", "SP-02", "AC-01",
        "AC-03", "AC-04", "AC-05", "AC-06",
        "OP-01", "OP-02", "OP-03", "OP-04", "OP-05", "OP-06", "OP-07", "OP-08", "OP-09", "OP-10",
    }
    _INFORMATIONAL_RULES = {"EXP-01", "EXP-02"}

    # Severity sections: ALL FAIL/WARN findings (including from standalone rules)
    all_severity_findings = [f for f in shown_findings if f.status.upper() in ("FAIL", "WARN", "ERROR")]
    grouped = rd.group_findings_by_severity(all_severity_findings)

    # Baseline Compliance: PASS not in standalone/informational
    baseline_findings = [f for f in shown_findings
                         if f.status.upper() == "PASS"
                         and f.rule_id not in _STANDALONE_RULES
                         and f.rule_id not in _INFORMATIONAL_RULES]

    # Informational findings
    informational_findings_list = [f for f in shown_findings if f.rule_id in _INFORMATIONAL_RULES]
    generated_at = generated_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    timestamp_html = f" &nbsp;|&nbsp; Generated {_e(generated_at)}" if show_timestamp else ""

    import policy_type as pt

    sections = ""
    for sev in ["HIGH", "MEDIUM", "LOW"]:
        items = grouped.get(sev, [])
        if items:
            sections += f'<div class="card"><h2>{sev.title()} Findings ({len(items)})</h2>{_findings_table(items, edited_messages=edited_messages, show_object=True)}{_inline_recommendations(items)}</div>'

    # TLS section
    tls_findings = [f for f in lb.lb_findings if f.rule_id.startswith("TLS-") and _finding_key(f) not in _excluded]
    tls_section = ""
    if tls_findings:
        tls_section = f'''
        <div class="card">
          <h2>TLS ({len(tls_findings)})</h2>
          {_findings_table(tls_findings, show_object=True, edited_messages=edited_messages)}
          {_inline_recommendations(tls_findings)}
        </div>
        '''

    # Certificates section
    cert_filtered = _filter(lb.certificate_findings)
    cert_section = ""
    if cert_filtered:
        cert_section = f'''
        <div class="card">
          <h2>Certificates ({len(cert_filtered)})</h2>
          {_findings_table(cert_filtered, show_object=True, edited_messages=edited_messages)}
          {_inline_recommendations(cert_filtered)}
        </div>
        '''

    # Baseline Compliance section (replaces "Passed Checks")
    baseline_section = ""
    if baseline_findings:
        baseline_section = f'<div class="card"><h2>Baseline Compliance ({len(baseline_findings)})</h2>{_findings_table(baseline_findings, edited_messages=edited_messages, show_object=True)}</div>'

    # Informational Findings section
    informational_section = ""
    if informational_findings_list:
        informational_section = f'<div class="card"><h2>Informational Findings ({len(informational_findings_list)})</h2>{_findings_table(informational_findings_list, edited_messages=edited_messages, show_object=True)}</div>'

    origin_section = ""
    origin_filtered = _filter(lb.origin_findings)
    if origin_filtered:
        origin_section = f'''
        <div class="card">
          <h2>Linked Origin Pool Findings ({len(origin_filtered)})</h2>
          {_findings_table(origin_filtered, show_object=True, edited_messages=edited_messages)}
        </div>
        '''

    health_check_section = ""
    hc_filtered = _filter(lb.health_check_findings)
    if hc_filtered:
        health_check_section = f'''
        <div class="card">
          <h2>Health Check ({len(hc_filtered)})</h2>
          {_findings_table(hc_filtered, show_object=True, edited_messages=edited_messages)}
        </div>
        '''

    not_purchased_section = ""
    if not_purchased_open:
        not_purchased_section = f'''
        <div class="card" style="background:#fffbe6; border:1px solid #f0d878;">
          <h2 style="border-bottom-color:#f0d878;">💡 Additional Opportunities ({len(not_purchased_open)})</h2>
          <p class="muted">These features are available but not currently purchased. Consider enabling them to further strengthen your security posture.</p>
          {_findings_table_opportunities_enhanced(not_purchased_open, edited_messages=edited_messages)}
        </div>
        '''

    # --- Service Policy section (Geo + HTTP + Other — excluding WAF exclusion, IP Rep, CSD) ---
    sp_section = ""
    if lb.service_policy_names:
        policy_groups = pt.group_policies_by_category(
            lb.service_policy_names, lb.service_policy_findings, policy_classifications)
        has_geo, geo_policies = pt.lb_geo_blocking_status(lb.service_policy_names, policy_classifications)
        has_http, http_policies = pt.lb_http_method_status(lb.service_policy_names, policy_classifications)

        sp_rows_html = []
        # Geo Blocking rollup
        geo_badge = f'<span class="badge" style="background:#27ae60">CONFIGURED</span>' if has_geo else f'<span class="badge" style="background:#e67e22">NOT DETECTED</span>'
        geo_detail = _e(", ".join(geo_policies)) if geo_policies else "No geo-blocking policy found"
        sp_rows_html.append(f"<tr><td>{geo_badge}</td><td>Geo Blocking</td><td>{geo_detail}</td></tr>")

        # HTTP Method Restriction rollup
        http_badge = f'<span class="badge" style="background:#27ae60">CONFIGURED</span>' if has_http else f'<span class="badge" style="background:#e67e22">NOT DETECTED</span>'
        http_detail = _e(", ".join(http_policies)) if http_policies else "No HTTP method restriction policy found"
        sp_rows_html.append(f"<tr><td>{http_badge}</td><td>HTTP Method Restriction</td><td>{http_detail}</td></tr>")

        # Other policies (separate Allow All with green badge)
        allow_all_policies = policy_groups.get(pt.ALLOW_ALL, [])
        other_only = policy_groups.get(pt.OTHER, [])
        for p in allow_all_policies:
            cat_badge = f'<span class="badge" style="background:#e67e22">ALLOW ALL</span>'
            sp_rows_html.append(f"<tr><td>{cat_badge}</td><td>Service Policy</td><td>{_e(p)}</td></tr>")
        for p in other_only:
            cat_badge = f'<span class="badge" style="background:#95a5a6">OTHER</span>'
            sp_rows_html.append(f"<tr><td>{cat_badge}</td><td>Service Policy</td><td>{_e(p)}</td></tr>")

        # Recommendations for missing geo/HTTP policies
        sp_rec_html = ""
        if not has_geo:
            sp_rec_html += (
                '<div class="rec-box rec-box-warn"><strong>Geo Blocking Recommendation:</strong><br>'
                'Configure a geo-blocking service policy to restrict traffic from countries or regions that are not expected to access this application. '
                'This reduces the attack surface and blocks traffic from high-risk geographies.'
                '<div><a href="https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection" target="_blank">'
                'https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection</a></div></div>'
            )
        if not has_http:
            sp_rec_html += (
                '<div class="rec-box rec-box-warn"><strong>HTTP Method Restriction Recommendation:</strong><br>'
                'Configure a service policy to restrict allowed HTTP methods (e.g., permit only GET, POST, HEAD) and block unnecessary or dangerous methods '
                '(e.g., PUT, DELETE, TRACE, OPTIONS). This limits the attack surface and prevents method-based exploitation.'
                '<div><a href="https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection" target="_blank">'
                'https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection</a></div></div>'
            )

        # Access Control findings (AC-01/03/04/05/06)
        ac_findings = [f for f in lb.lb_findings if f.rule_id in ("AC-01", "AC-03", "AC-04", "AC-05", "AC-06") and _finding_key(f) not in _excluded]
        ac_html = ""
        if ac_findings:
            ac_html = f'<h3 style="margin-top:16px;font-size:14px;">Access Control Findings ({len(ac_findings)})</h3>'
            ac_html += _findings_table(ac_findings, show_object=True, edited_messages=edited_messages)

        sp_section = f'''
        <div class="card">
          <h2>Service Policies ({len(sp_rows_html)})</h2>
          <p class="muted">Service policies assigned to this LB: {_e(", ".join(lb.service_policy_names))}</p>
          <table>
            <thead><tr><th style="width:140px">Status</th><th>Check</th><th>Details</th></tr></thead>
            <tbody>{''.join(sp_rows_html)}</tbody>
          </table>
          {sp_rec_html}
          {ac_html}
        </div>
        '''

    # --- IP Reputation section ---
    ip_rep_findings = [f for f in lb.lb_findings if f.rule_id == "AC-02" and _finding_key(f) not in _excluded]
    ip_rep_sp = pt.filter_findings_by_category(
        lb.service_policy_findings, pt.IP_REPUTATION, lb.service_policy_names, policy_classifications)
    tc_ip_rep = pt.get_trusted_clients_ip_rep_findings(lb.name, all_findings) if all_findings and show_trusted_clients else []
    ip_rep_section = ""
    if ip_rep_findings or ip_rep_sp or tc_ip_rep:
        ip_content = ""
        if ip_rep_findings:
            ip_content += _findings_table(ip_rep_findings, edited_messages=edited_messages)
            ip_content += _inline_recommendations(ip_rep_findings)
        if ip_rep_sp:
            ip_content += f'<h3 style="margin-top:16px;font-size:14px;">IP Reputation Service Policies ({len(ip_rep_sp)})</h3>'
            ip_content += _findings_table(ip_rep_sp, show_object=True, edited_messages=edited_messages)
        if tc_ip_rep:
            ip_content += f'<h3 style="margin-top:16px;font-size:14px;">Trusted Clients — IP Reputation ({len(tc_ip_rep)})</h3>'
            ip_content += _findings_table(tc_ip_rep, show_object=True, edited_messages=edited_messages)
        total_ip = len(ip_rep_findings) + len(ip_rep_sp) + len(tc_ip_rep)
        ip_rep_section = f'''
        <div class="card">
          <h2>IP Reputation ({total_ip})</h2>
          {ip_content}
        </div>
        '''

    # --- Client-Side Defense section (only if entitled) ---
    from product_entitlements import is_entitled as _is_entitled
    _ent = entitlements or {}
    csd_findings = [f for f in lb.lb_findings if f.rule_id in ("CSD-01", "CSD-02") and _is_entitled(f, _ent) and _finding_key(f) not in _excluded]
    csd_sp = pt.filter_findings_by_category(
        lb.service_policy_findings, pt.CLIENT_SIDE_DEFENSE, lb.service_policy_names, policy_classifications) if csd_findings else []
    csd_section = ""
    if csd_findings or csd_sp:
        csd_content = ""
        if csd_findings:
            csd_content += _findings_table(csd_findings, edited_messages=edited_messages)
            csd_content += _inline_recommendations(csd_findings)
        if csd_sp:
            csd_content += f'<h3 style="margin-top:16px;font-size:14px;">CSD Service Policies ({len(csd_sp)})</h3>'
            csd_content += _findings_table(csd_sp, show_object=True, edited_messages=edited_messages)
        total_csd = len(csd_findings) + len(csd_sp)
        csd_section = f'''
        <div class="card">
          <h2>Client-Side Defense ({total_csd})</h2>
          {csd_content}
        </div>
        '''

    # --- DDoS Protection section ---
    ddos_findings = [f for f in lb.lb_findings if f.rule_id in ("DDOS-01", "DDOS-02", "DDOS-03") and _finding_key(f) not in _excluded]
    tc_threat_intel = pt.get_trusted_clients_threat_intel_findings(lb.name, all_findings) if all_findings and show_trusted_clients else []
    ddos_section = ""
    if ddos_findings or tc_threat_intel:
        ddos_content = ""
        if ddos_findings:
            ddos_content += _findings_table(ddos_findings, edited_messages=edited_messages)
        # DDoS default threshold recommendation
        uses_default = any(
            isinstance(f.current_value, dict) and "default_rps_threshold" in f.current_value
            for f in ddos_findings
        )
        if uses_default:
            ddos_content += (
                '<div class="rec-box rec-box-info">'
                "<strong>Recommendation:</strong><br>"
                "This LB is using the platform default RPS threshold. "
                "Review and tune the threshold to match the application's actual backend capacity. "
                "A threshold that is too high may not protect against slow DDoS attacks, "
                "while a threshold that is too low may cause false positives under legitimate traffic spikes."
                "</div>"
            )
        if tc_threat_intel:
            ddos_content += f'<h3 style="margin-top:16px;font-size:14px;">Trusted Clients — Threat Intel ({len(tc_threat_intel)})</h3>'
            ddos_content += _findings_table(tc_threat_intel, show_object=True, edited_messages=edited_messages)
        ddos_section = f'''
        <div class="card">
          <h2>DDoS Protection ({len(ddos_findings) + len(tc_threat_intel)})</h2>
          {ddos_content}
        </div>
        '''

    # --- Bot Defense section (BOT-01, BOT-04 — product-gated) ---
    bot_findings = [f for f in lb.lb_findings if f.rule_id in ("BOT-01", "BOT-04") and _is_entitled(f, _ent) and _finding_key(f) not in _excluded]
    bot_section = ""
    if bot_findings:
        bot_content = _findings_table(bot_findings, edited_messages=edited_messages)
        bot_content += _inline_recommendations(bot_findings)
        bot_section = f'''
        <div class="card">
          <h2>Bot Defense ({len(bot_findings)})</h2>
          {bot_content}
        </div>
        '''

    # --- API Protection section (API-* — some product-gated) ---
    api_prot_findings = [f for f in lb.lb_findings if f.rule_id.startswith("API-") and _finding_key(f) not in _excluded] if _ent.get("api_protection", True) else []
    api_prot_section = ""
    if api_prot_findings:
        api_content = _findings_table(api_prot_findings, edited_messages=edited_messages)
        api_content += _inline_recommendations(api_prot_findings)
        api_prot_section = f'''
        <div class="card">
          <h2>API Protection ({len(api_prot_findings)})</h2>
          {api_content}
        </div>
        '''

    # --- Rate Limiting section (RL-01, RL-02 — product-gated) ---
    rate_limit_findings = [f for f in lb.lb_findings if f.rule_id in ("RL-01", "RL-02") and _is_entitled(f, _ent) and _finding_key(f) not in _excluded]
    rate_limit_section = ""
    if rate_limit_findings:
        rl_content = _findings_table(rate_limit_findings, edited_messages=edited_messages)
        rl_content += _inline_recommendations(rate_limit_findings)
        rate_limit_section = f'''
        <div class="card">
          <h2>Rate Limiting ({len(rate_limit_findings)})</h2>
          {rl_content}
        </div>
        '''

    # --- Malicious User Detection section (BOT-02, BOT-03 — product-gated) ---
    mud_findings = [f for f in lb.lb_findings if f.rule_id in ("BOT-02", "BOT-03") and _is_entitled(f, _ent) and _finding_key(f) not in _excluded]
    mud_section = ""
    if mud_findings:
        mud_content = _findings_table(mud_findings, edited_messages=edited_messages)
        mud_content += _inline_recommendations(mud_findings)
        mud_section = f'''
        <div class="card">
          <h2>Malicious User Detection ({len(mud_findings)})</h2>
          {mud_content}
        </div>
        '''

    # --- Malware Detection section (WAF-03) ---
    malware_findings = [f for f in lb.lb_findings if f.rule_id == "WAF-03" and _finding_key(f) not in _excluded]
    malware_section = ""
    if malware_findings or mud_findings:
        malware_content = ""
        if malware_findings:
            malware_content += _findings_table(malware_findings, edited_messages=edited_messages)
            malware_content += _inline_recommendations(malware_findings)
        if mud_findings:
            malware_content += f'<h3 style="margin-top:16px;font-size:14px;">Malicious User Detection ({len(mud_findings)})</h3>'
            malware_content += _findings_table(mud_findings, edited_messages=edited_messages)
            malware_content += _inline_recommendations(mud_findings)
        malware_section = f'''
        <div class="card">
          <h2>Malware Detection ({len(malware_findings) + len(mud_findings)})</h2>
          {malware_content}
        </div>
        '''

    waf_mode_html = ""
    # v2: WAF mode comes from WAFP-01 finding (lb.waf_mode)
    effective_waf_mode = lb.waf_mode or waf_mode or ""
    if effective_waf_mode:
        waf_mode_html = f"<div class='muted'>WAF Enforcement Mode: {_e(effective_waf_mode)}</div>"

    # --- WAF Policy Details section (WAFP-* findings, now directly linked to LBs) ---
    waf_policy_section = ""
    wafp_filtered = _filter(lb.waf_policy_findings)
    if wafp_filtered:
        wafp_content = _findings_table(wafp_filtered, show_object=True, edited_messages=edited_messages)
        wafp_content += _inline_recommendations(wafp_filtered)
        waf_policy_section = f'''
        <div class="card">
          <h2>WAF Policy Details ({len(wafp_filtered)})</h2>
          {wafp_content}
        </div>
        '''

    tenant_context_section = ""
    if tenant_context:
        from manual_checklist import MANUAL_CHECKLIST_ITEMS
        checklist_rec_map = {item.label: item for item in MANUAL_CHECKLIST_ITEMS}
        # Auto-detected item recommendations and messages
        _AUTO_RECS = {
            "Alert Policies Active": (
                "Configure alert policies to receive notifications for security events and operational issues.",
                "https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
            ),
            "SIEM / Global Log Receiver Configured": (
                "Configure a Global Log Receiver to forward security logs to your SIEM for centralized monitoring, correlation, and incident response.",
                "https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
            ),
        }
        # Get messages from tenant findings for display
        _tenant_messages = {}
        if all_findings:
            for f in all_findings:
                if f.rule_id == "TENANT-ALERT-01":
                    _tenant_messages["Alert Policies Active"] = f.message
                elif f.rule_id == "TENANT-LOG-01":
                    _tenant_messages["SIEM / Global Log Receiver Configured"] = f.message

        tc_rows = []
        for label, value in tenant_context.get("summary_lines", []):
            val_str = str(value)
            if val_str in ("True", "Yes"):
                badge = f'<span class="badge" style="background:#27ae60">YES</span>'
            elif val_str in ("False", "No"):
                badge = f'<span class="badge" style="background:#c0392b">NO</span>'
            elif val_str in ("N/A",):
                badge = f'<span class="badge" style="background:#95a5a6">N/A</span>'
            elif val_str == "Not Reviewed":
                badge = f'<span class="badge" style="background:#aaa">&mdash;</span>'
            else:
                badge = f'<span class="badge" style="background:#e67e22">{_e(val_str)}</span>'

            # Show message if available
            msg_html = ""
            if label in _tenant_messages:
                msg_html = f'<div class="muted" style="margin-top:4px;">{_e(_tenant_messages[label])}</div>'

            # Build recommendation/best practice (always shown via chevron)
            needs_action = val_str in ("False", "No", "Not Reviewed")
            rec_text = ""
            ref_url = ""
            if label in checklist_rec_map:
                item = checklist_rec_map[label]
                rec_text = item.recommendation or ""
                ref_url = item.reference_url or ""
            elif label in _AUTO_RECS:
                rec_text, ref_url = _AUTO_RECS[label]

            if rec_text:
                open_attr = " open" if needs_action else ""
                rec_label = "Recommendation" if needs_action else "Best Practice"
                rec_class = "rec-box rec-box-warn" if needs_action else "rec-box rec-box-info"
                ref_html = f' &nbsp;|&nbsp; <a href="{_e(ref_url)}" target="_blank">Reference ↗</a>' if ref_url else ""
                chevron_class = "chevron-open" if needs_action else "chevron-closed"
                detail_display = "" if needs_action else ' style="display:none;"'
                inline_rec = (
                    f'<div class="rec-row-inline"{detail_display}>'
                    f'<div class="{rec_class}" style="margin-top:6px;">'
                    f'<strong>{rec_label}:</strong> {_e(rec_text)}{ref_html}</div></div>'
                )
                arrow_html = f'<span class="{chevron_class}" style="cursor:pointer;" onclick="toggleTenantRec(this)">&#x276F;</span>'
            else:
                inline_rec = ""
                arrow_html = ""

            tc_rows.append(
                f"<tr>"
                f"<td class='chevron-cell'>{arrow_html}</td>"
                f"<td>{badge}</td>"
                f"<td>{_e(label)}{msg_html}{inline_rec}</td>"
                f"</tr>"
            )
        tenant_context_section = f'''
        <div class="card">
          <h2>Tenant-Wide Context ({len(tc_rows)})</h2>
          <table>
            <thead><tr><th style="width:28px"></th><th style="width:120px">Status</th><th>Check</th></tr></thead>
            <tbody>{''.join(tc_rows)}</tbody>
          </table>
        </div>
        '''

    # WAF section (LB-specific WAF configuration — styled as a table card)
    waf_section = ""
    if lb.waf_assigned or waf_mode:
        from manual_checklist import WAF_MODE_RECOMMENDATION, WAF_MODE_REFERENCE_URL
        from manual_checklist import WAF_EXCLUSION_RECOMMENDATION, WAF_EXCLUSION_REFERENCE_URL
        waf_rows_html = []

        # WAF Policy row
        policy_badge = f'<span class="badge" style="background:#27ae60">ASSIGNED</span>' if lb.waf_assigned else f'<span class="badge" style="background:#c0392b">NOT ASSIGNED</span>'
        waf_rows_html.append(f"<tr><td>{policy_badge}</td><td>WAF Policy</td><td>{_e(lb.waf_policy_name or 'None')}</td></tr>")

        # Enforcement Mode row
        if waf_mode:
            mode_color = "#27ae60" if waf_mode == "Blocking" else "#e67e22" if waf_mode == "Monitoring" else "#95a5a6"
            mode_badge = f'<span class="badge" style="background:{mode_color}">{_e(waf_mode.upper())}</span>'
            waf_rows_html.append(f"<tr><td>{mode_badge}</td><td>Enforcement Mode</td><td>{_e(waf_mode)}</td></tr>")

        # WAF Exclusion Rules row (from WAF-02 finding or service policy detection)
        waf_excl_finding = next((f for f in lb.lb_findings if f.rule_id == "WAF-02"), None)
        has_waf_excl = tenant_context.get("waf_exclusion_detected", False) if tenant_context else False
        waf_excl_policies = tenant_context.get("waf_exclusion_policies", []) if tenant_context else []
        waf_excl_notes = tenant_context.get("waf_exclusion_notes", "") if tenant_context else ""

        _EXCL_ARTICLE_URL = "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-tos/advanced-security/manage-waf-exclusion-rules"
        if waf_excl_finding:
            # Any exclusion rules found → show as WARN (needs review)
            has_exclusions = "no" not in (waf_excl_finding.message or "").lower() or waf_excl_finding.status.upper() != "PASS"
            if has_exclusions and "no waf exclusion" not in (waf_excl_finding.message or "").lower():
                excl_badge = f'<span class="badge" style="background:#e2231a">REVIEW</span>'
                excl_detail = _e(waf_excl_finding.message)
                excl_detail += f'<div style="margin-top:6px;font-size:12px;"><a href="{_EXCL_ARTICLE_URL}" target="_blank">WAF Exclusion Rules Reference ↗</a></div>'
            else:
                excl_badge = f'<span class="badge" style="background:#95a5a6">NONE</span>'
                excl_detail = _e(waf_excl_finding.message)
            if waf_excl_notes:
                excl_detail += f'<div class="muted" style="margin-top:4px;">{_e(waf_excl_notes)}</div>'
            waf_rows_html.append(f"<tr><td>{excl_badge}</td><td>WAF Exclusion Rules</td><td>{excl_detail}</td></tr>")
        elif has_waf_excl:
            excl_badge = f'<span class="badge" style="background:#e67e22">IN USE</span>'
            excl_detail = _e(", ".join(waf_excl_policies))
            if waf_excl_notes:
                excl_detail += f'<div class="muted" style="margin-top:4px;">{_e(waf_excl_notes)}</div>'
            waf_rows_html.append(f"<tr><td>{excl_badge}</td><td>WAF Exclusion Rules</td><td>{excl_detail}</td></tr>")
        else:
            excl_badge = f'<span class="badge" style="background:#95a5a6">NONE</span>'
            excl_detail = "No exclusion policies detected"
            if waf_excl_notes:
                excl_detail += f'<div class="muted" style="margin-top:4px;">{_e(waf_excl_notes)}</div>'
            waf_rows_html.append(f"<tr><td>{excl_badge}</td><td>WAF Exclusion Rules</td><td>{excl_detail}</td></tr>")

        # Recommendation if not blocking
        rec_html = ""
        if waf_mode and waf_mode != "Blocking":
            rec_text = _e(WAF_MODE_RECOMMENDATION).replace("\n", "<br>")
            ref_html = f'<div><a href="{_e(WAF_MODE_REFERENCE_URL)}" target="_blank">{_e(WAF_MODE_REFERENCE_URL)}</a></div>'
            rec_html = f'<div class="rec-box rec-box-warn"><strong>Recommendation:</strong><br>{rec_text}{ref_html}</div>'

        # Recommendation for WAF exclusion review (only when exclusions exist)
        excl_rec_html = ""
        if has_waf_excl:
            excl_rec_text = _e(WAF_EXCLUSION_RECOMMENDATION).replace("\n", "<br>")
            excl_ref = f'<div><a href="{_e(WAF_EXCLUSION_REFERENCE_URL)}" target="_blank">{_e(WAF_EXCLUSION_REFERENCE_URL)}</a></div>'
            excl_rec_html = f'<div class="rec-box rec-box-info"><strong>Review Recommendation:</strong><br>{excl_rec_text}{excl_ref}</div>'

        # WAF Configuration findings (WAF-01/04/05)
        waf_cfg_findings = [f for f in lb.lb_findings if f.rule_id in ("WAF-01", "WAF-04", "WAF-05") and _finding_key(f) not in _excluded]
        waf_cfg_html = ""
        if waf_cfg_findings:
            waf_cfg_html = f'<h3 style="margin-top:16px;font-size:14px;">WAF Configuration Findings ({len(waf_cfg_findings)})</h3>'
            waf_cfg_html += _findings_table(waf_cfg_findings, edited_messages=edited_messages)
            waf_cfg_html += _inline_recommendations(waf_cfg_findings)

        # Trusted Clients WAF (optional)
        tc_waf_html = ""
        if show_trusted_clients and all_findings:
            tc_waf = pt.get_trusted_clients_waf_findings(lb.name, all_findings)
            if tc_waf:
                tc_waf_html = f'<h3 style="margin-top:16px;font-size:14px;">Trusted Clients — WAF ({len(tc_waf)})</h3>'
                tc_waf_html += _findings_table(tc_waf, show_object=True, edited_messages=edited_messages)

        waf_section = f'''
        <div class="card">
          <h2>WAF Configuration ({len(waf_rows_html)})</h2>
          <table>
            <thead><tr><th style="width:120px">Status</th><th>Check</th><th>Details</th></tr></thead>
            <tbody>{''.join(waf_rows_html)}</tbody>
          </table>
          {rec_html}
          {excl_rec_html}
          {waf_cfg_html}
          {tc_waf_html}
        </div>
        '''

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Posture Review - {_e(lb.name)}</title>
{_base_css()}
</head><body>
  <div class="header">
    <h1>Security Posture Review</h1>
    <div class="sub">Load Balancer: {_e(lb.name)} &nbsp;|&nbsp; Tenant: {_e(summary.tenant)} &nbsp;|&nbsp;
      Namespace: {_e(summary.namespace)}{timestamp_html}</div>
  </div>
  <div class="container">
    <div class="card">
      <h2>Executive Summary</h2>
      <div style="display:flex; align-items:center; gap:24px; flex-wrap:wrap;">
        <div>
          <div class="score" style="color:{rd.health_color(s['health'])}">{s['health_icon']} {s['health']}</div>
          <div class="muted">WAF policy: {_e(s['waf_policy_name'])} ({'assigned' if s['waf_assigned'] else 'not assigned'})</div>
          {waf_mode_html}
        </div>
        <div style="flex:1;">
          {_stat_grid([
              ("Critical", s['critical']), ("High", s['high']), ("Medium", s['medium']),
              ("Low", s['low']), ("Passed", s['passed']), ("Informational", s['informational']),
              ("Total Assessed", s['total']),
          ])}
        </div>
      </div>
    </div>

    {sections}
    {tls_section}
    {cert_section}
    {origin_section}
    {health_check_section}
    {waf_section}
    {waf_policy_section}
    {bot_section}
    {api_prot_section}
    {malware_section}
    {ddos_section}
    {csd_section}
    {sp_section}
    {rate_limit_section}
    {ip_rep_section}
    {informational_section}
    {baseline_section}
    {tenant_context_section}

    {not_purchased_section}

    <div class="footer">
      Generated by XC Security Report Generator &nbsp;|&nbsp; F5 Distributed Cloud Security Posture Review
    </div>
  </div>
</body></html>"""


def _manual_checklist_html(checklist_answers) -> str:
    from manual_checklist import MANUAL_CHECKLIST_ITEMS

    status_colors = {
        "Yes": "#27ae60", "No": "#c0392b", "N/A": "#999", "Not Reviewed": "#aaa",
    }
    status_labels = {
        "Not Reviewed": "\u2014",
    }

    rows = []
    for item in MANUAL_CHECKLIST_ITEMS:
        answer = (checklist_answers or {}).get(item.id, {"status": "Not Reviewed", "notes": ""})
        status = answer.get("status", "Not Reviewed")
        notes = answer.get("notes", "")
        color = status_colors.get(status, "#999")
        notes_html = f'<div class="muted">{_e(notes)}</div>' if notes else ""

        # Show recommendation when answered "No" or "N/A"
        rec_html = ""
        if status in ("No", "N/A") and item.recommendation:
            rec_text = _e(item.recommendation).replace("\n", "<br>")
            ref_html = f'<div><a href="{_e(item.reference_url)}" target="_blank">{_e(item.reference_url)}</a></div>' if item.reference_url else ""
            rec_html = f'<div class="rec-box rec-box-warn"><strong>Recommendation:</strong><br>{rec_text}{ref_html}</div>'

        display_status = status_labels.get(status, status)
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{_e(display_status)}</span></td>
          <td>{_e(item.label)}{notes_html}{rec_html}</td>
        </tr>
        """)

    return f"""
    <table>
      <thead><tr><th style="width:120px">Status</th><th>Item</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def render_namespace_report(summary, reports, ns, generated_at=None, checklist_answers=None,
                             entitlements=None, all_findings=None, edited_messages=None,
                             policy_overrides=None, waf_modes=None, show_timestamp=True) -> str:
    not_purchased_open = []
    if entitlements and all_findings is not None:
        from product_entitlements import split_findings, PRODUCTS
        ns_summary = rd.namespace_summary_entitled(summary, reports, all_findings, entitlements)
        _, not_purchased = split_findings(all_findings, entitlements)
        not_purchased_open = [f for f in not_purchased if f.status.upper() != "PASS"]
        not_purchased_products = [p.label for p in PRODUCTS if not entitlements.get(p.id, True)]
        lb_summary_fn = lambda lb: rd.lb_summary_entitled(lb, entitlements, checklist_answers=checklist_answers)
    else:
        ns_summary = rd.namespace_summary(summary, reports)
        not_purchased_products = []
        lb_summary_fn = lambda lb: rd.lb_summary(lb, checklist_answers=checklist_answers)

    generated_at = generated_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    timestamp_html = f" &nbsp;|&nbsp; Generated {_e(generated_at)}" if show_timestamp else ""

    lb_rows = "".join(
        f"<tr><td>{_e(lb_summary_fn(lb)['name'])}</td>"
        f"<td>{lb_summary_fn(lb)['health_icon']} {_e(lb_summary_fn(lb)['health'])}</td>"
        f"<td>{lb_summary_fn(lb)['critical']}</td><td>{lb_summary_fn(lb)['high']}</td>"
        f"<td>{lb_summary_fn(lb)['total']}</td></tr>"
        for lb in sorted(reports.values(), key=lambda x: x.name.lower())
    )

    not_purchased_section = ""
    if not_purchased_open:
        not_purchased_section = f'''
        <div class="card">
          <h2>💡 Additional Opportunities ({len(not_purchased_open)})</h2>
          <p class="muted">Potential enhancements to further strengthen the security posture.</p>
          {_findings_table_with_refs(not_purchased_open, edited_messages=edited_messages)}
        </div>
        '''

    waf_mode_section = ""
    if waf_modes:
        set_modes = {k: v for k, v in waf_modes.items() if v and v != "Not Set"}
        if set_modes:
            rows = "".join(
                f"<tr><td>{_e(name)}</td><td>{_e(mode)}</td></tr>"
                for name, mode in sorted(set_modes.items())
            )
            waf_mode_section = f'''
            <div class="card">
              <h2>WAF Enforcement Mode</h2>
              <table><thead><tr><th>Load Balancer</th><th>Mode</th></tr></thead>
                <tbody>{rows}</tbody></table>
            </div>
            '''

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Namespace Security Report - {_e(ns_summary['namespace'])}</title>
{_base_css()}
</head><body>
  <div class="header">
    <h1>Namespace Security Posture Review</h1>
    <div class="sub">Tenant: {_e(ns_summary['tenant'])} &nbsp;|&nbsp; Namespace: {_e(ns_summary['namespace'])}
      {timestamp_html}</div>
  </div>
  <div class="container">
    <div class="card">
      <h2>Executive Summary</h2>
      {_stat_grid([
          ("Security Score", ns_summary['score']), ("Load Balancers", ns_summary['load_balancers']),
          ("Critical", ns_summary['critical']), ("High", ns_summary['high']),
          ("Passed", ns_summary['passed']), ("Total Checks", ns_summary['total']),
      ])}
    </div>

    <div class="card">
      <h2>Load Balancers ({len(reports)})</h2>
      <table>
        <thead><tr><th>Name</th><th>Health</th><th>Critical</th><th>High</th><th>Total Checks</th></tr></thead>
        <tbody>{lb_rows}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Tenant-Wide Findings ({len(ns.tenant_findings)})</h2>
      {_findings_table(ns.tenant_findings, edited_messages=edited_messages)}
    </div>

    <div class="card">
      <h2>WAF Policy Findings - Tenant Wide ({len(ns.waf_policy_findings)})</h2>
      {_findings_table(ns.waf_policy_findings, edited_messages=edited_messages)}
    </div>

    {waf_mode_section}

    <div class="card">
      <h2>Unassigned Service Policies ({len(ns.orphan_service_policy_findings)})</h2>
      {_findings_table(ns.orphan_service_policy_findings, show_object=True, edited_messages=edited_messages,
                        policy_overrides=policy_overrides, check_applicability=True)}
    </div>

    <div class="card">
      <h2>Unmatched Origin Pools ({len(ns.orphan_origin_pool_findings)})</h2>
      {_findings_table(ns.orphan_origin_pool_findings, show_object=True, edited_messages=edited_messages)}
    </div>

    {not_purchased_section}

    <div class="card">
      <h2>Logging &amp; Alerting ({len(ns.log_receiver_findings) + len(ns.alert_policy_findings) + len(ns.alert_receiver_findings)})</h2>
      {_findings_table(ns.log_receiver_findings + ns.alert_policy_findings + ns.alert_receiver_findings, show_object=True, edited_messages=edited_messages)}
    </div>

    <div class="card">
      <h2>Manual Review Checklist</h2>
      {_manual_checklist_html(checklist_answers)}
    </div>

    <div class="footer">
      Generated by XC Security Report Generator &nbsp;|&nbsp; F5 Distributed Cloud Security Posture Review
    </div>
  </div>
</body></html>"""
