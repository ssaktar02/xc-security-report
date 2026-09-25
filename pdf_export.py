"""
PDF exporter — converts the HTML report to a matching PDF using xhtml2pdf.

Features:
- Cover page with F5 logo, customer/tenant name, date
- Page breaks between major sections
- Header/footer with tenant name and page numbers
- Conditional row coloring (FAIL=red tint, WARN=amber tint)
- Health score visual indicator
- All recommendations expanded
"""

import base64
import io
import os
import re
from datetime import datetime

from xhtml2pdf import pisa


_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def _get_logo_base64() -> str:
    """Load the F5 logo as a base64-encoded data URI."""
    logo_path = os.path.join(_ASSETS_DIR, "f5-logo.png")
    if not os.path.exists(logo_path):
        return ""
    with open(logo_path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def _cover_page(tenant: str, lb_name: str, namespace: str, generated_at: str) -> str:
    """Generate a single-page cover using one table with controlled row heights."""
    logo_b64 = _get_logo_base64()
    logo_html = f'<img src="data:image/png;base64,{logo_b64}" width="90" />' if logo_b64 else ""

    return f"""
    <div style="page-break-after:always;">
    <table style="border:none;" cellpadding="0" cellspacing="0">
      <tr><td style="border:none; text-align:center; padding-top:100px; padding-bottom:10px;">{logo_html}</td></tr>
      <tr><td style="border:none; text-align:center; font-size:26px; font-weight:bold; color:#1a1a2e; padding:10px 0 4px 0;">Security Posture Review</td></tr>
      <tr><td style="border:none; text-align:center; font-size:14px; color:#666; padding:2px 0 30px 0;">F5 Distributed Cloud</td></tr>
      <tr><td style="border:none; text-align:center; font-size:12px; color:#333; padding:4px 0;"><strong>Tenant:</strong> {tenant}</td></tr>
      <tr><td style="border:none; text-align:center; font-size:12px; color:#333; padding:4px 0;"><strong>Load Balancer:</strong> {lb_name}</td></tr>
      <tr><td style="border:none; text-align:center; font-size:12px; color:#333; padding:4px 0;"><strong>Namespace:</strong> {namespace}</td></tr>
      <tr><td style="border:none; text-align:center; font-size:12px; color:#333; padding:4px 0 30px 0;"><strong>Date:</strong> {generated_at}</td></tr>
      <tr><td style="border:none; text-align:center; font-size:10px; color:#e74c3c; letter-spacing:3px; padding:20px 0;">CONFIDENTIAL</td></tr>
    </table>
    </div>
    """


def _extract_metadata(html: str) -> dict:
    """Extract tenant, LB name, namespace, and generated date from the HTML."""
    meta = {"tenant": "", "lb_name": "", "namespace": "", "generated_at": ""}
    # Extract from the sub div: "Load Balancer: X | Tenant: Y | Namespace: Z | Generated ..."
    m = re.search(r'Load Balancer:\s*([^&<]+)', html)
    if m:
        meta["lb_name"] = m.group(1).strip()
    m = re.search(r'Tenant:\s*([^&<]+)', html)
    if m:
        meta["tenant"] = m.group(1).strip()
    m = re.search(r'Namespace:\s*([^&<]+)', html)
    if m:
        meta["namespace"] = m.group(1).strip()
    m = re.search(r'Generated\s+([^<]+)', html)
    if m:
        meta["generated_at"] = m.group(1).strip()
    else:
        meta["generated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return meta


def _add_row_coloring(html: str) -> str:
    """Add background tint to REVIEW (FAIL) and CAUTION (WARN) rows for visual scanning."""
    # REVIEW rows — light red background
    html = re.sub(
        r'<tr class="finding-row"([^>]*)>(.*?>REVIEW</span>)',
        r'<tr class="finding-row" style="background-color:#fde8e8;"\1>\2',
        html,
    )
    # CAUTION rows — light amber background
    html = re.sub(
        r'<tr class="finding-row"([^>]*)>(.*?>CAUTION</span>)',
        r'<tr class="finding-row" style="background-color:#fef3e2;"\1>\2',
        html,
    )
    return html


def _health_score_indicator(html: str) -> str:
    """Replace the text health score with a visual colored block indicator."""
    # Find the score div and enhance it
    def _replace_score(m):
        color = m.group(1)
        content = m.group(2)
        return (
            f'<div class="score" style="color:{color}; '
            f'border-left: 6px solid {color}; padding-left: 12px;">{content}</div>'
        )
    html = re.sub(
        r'<div class="score" style="color:([^"]+)">([^<]+)</div>',
        _replace_score,
        html,
    )
    return html


def _prepare_html_for_pdf(html: str) -> str:
    """Adapt the HTML report for PDF rendering."""
    # Extract metadata for cover page and headers
    meta = _extract_metadata(html)

    # 1. Remove all display:none from rec-rows (show all recommendations)
    html = html.replace('class="rec-row" style="display:none;"', 'class="rec-row"')
    html = html.replace('class="rec-row-inline" style="display:none;"', 'class="rec-row-inline"')

    # 2. All chevrons should show as open (downward)
    html = html.replace('class="chevron-closed"', 'class="chevron-open"')

    # 3. Remove the toggle JS (not needed in PDF)
    html = re.sub(r'<script>.*?</script>', '', html, flags=re.DOTALL)

    # 4. Remove onclick handlers
    html = html.replace(' onclick="toggleRec(this)"', '')
    html = html.replace(' onclick="toggleTenantRec(this)"', '')

    # 5. Add conditional row coloring
    html = _add_row_coloring(html)

    # 6. Enhance health score indicator
    html = _health_score_indicator(html)

    # 6b. Remove width:100% from tables (xhtml2pdf chokes on percentage widths)
    html = re.sub(r'width:\s*100%\s*;?', '', html)
    html = re.sub(r'width="100%"', '', html)

    # 6c. Convert stat-grid divs to actual HTML table for xhtml2pdf
    def _convert_stat_grid(m):
        grid_html = m.group(0)
        cells = re.findall(r'<div class="stat"><div class="n">([^<]+)</div><div class="l">([^<]+)</div></div>', grid_html)
        if not cells:
            return grid_html
        row = ''.join(
            f'<td style="border:none; text-align:center; padding:6px 4px; background:#f8f9fa;">'
            f'<div style="font-size:9px; color:#888;">{label}</div>'
            f'<div style="font-size:16px; font-weight:bold;">{value}</div></td>'
            for value, label in cells
        )
        return f'<table style="border:none;"><tr>{row}</tr></table>'

    html = re.sub(r'<div class="stat-grid">.*?</div></div></div>', _convert_stat_grid, html, flags=re.DOTALL)

    # 7. Add page breaks before major sections
    html = re.sub(
        r'(<div class="card">\s*<h2>(?:High|Medium|Low|TLS|Certificates|'
        r'Linked Origin Pool|Health Check|WAF Configuration|WAF Policy|'
        r'Bot Defense|API Protection|Malware Detection|DDoS Protection|'
        r'Client-Side Defense|Service Policies|Rate Limiting|IP Reputation|'
        r'Informational Findings|Baseline Compliance|Tenant-Wide Context|'
        r'Additional Opportunities))',
        r'<div style="page-break-before:always;"></div>\1',
        html,
    )

    # 8. Generate cover page
    cover = _cover_page(
        meta["tenant"], meta["lb_name"], meta["namespace"], meta["generated_at"]
    )

    # 9. Inject PDF-specific CSS and cover page
    pdf_css = f"""
    <style>
      @page {{
        size: A4 portrait;
        margin: 2cm 1.5cm 2.5cm 1.5cm;
        @frame header {{
          -pdf-frame-content: pdf-header;
          top: 0.5cm;
          margin-left: 1.5cm;
          margin-right: 1.5cm;
          height: 1.2cm;
        }}
        @frame footer {{
          -pdf-frame-content: pdf-footer;
          bottom: 0.3cm;
          margin-left: 1.5cm;
          margin-right: 1.5cm;
          height: 1.5cm;
        }}
      }}
      @page cover {{
        size: A4 portrait;
        margin: 2cm 1.5cm;
      }}
      body {{
        font-size: 11px;
        background: white;
      }}
      #pdf-header {{
        font-size: 9px;
        color: #666;
        border-bottom: 1px solid #ddd;
        padding-bottom: 4px;
      }}
      #pdf-footer {{
        font-size: 9px;
        color: #666;
        border-top: 1px solid #ddd;
        padding-top: 4px;
        text-align: center;
      }}
      .header {{
        background-color: #1a1a2e;
        color: white;
        -webkit-print-color-adjust: exact;
        padding: 18px 24px;
      }}
      .container {{
        padding: 12px 8px;
      }}
      .card {{
        page-break-inside: avoid;
        box-shadow: none;
        border: 1px solid #ddd;
        margin-bottom: 14px;
        padding: 14px 16px;
      }}
      table {{
        font-size: 11px;
      }}
      th, td {{
        padding: 6px 8px;
        font-size: 11px;
      }}
      .badge {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }}
      .stat {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }}
      .stat-grid {{
        display: table;
      }}
      .stat-grid .stat {{
        display: table-cell;
        padding: 8px 4px;
      }}
      .chevron-cell {{
        width: 20px;
        font-size: 10px;
      }}
      .rec-box {{
        page-break-inside: avoid;
        font-size: 11px;
      }}
      .finding-row {{
        cursor: default;
      }}
      .score {{
        font-size: 28px;
      }}
      a {{ color: #2563eb; }}
      .footer {{
        page-break-before: auto;
        margin-top: 20px;
      }}
    </style>
    """

    # Header/footer content (xhtml2pdf renders these from named divs)
    header_footer = f"""
    <div id="pdf-header">
      F5 Distributed Cloud — Security Posture Review &nbsp;|&nbsp; {meta['tenant']} &nbsp;|&nbsp; {meta['lb_name']}
    </div>
    <div id="pdf-footer">
      Page <pdf:pagenumber/> of <pdf:pagecount/> &nbsp;|&nbsp; Generated {meta['generated_at']} &nbsp;|&nbsp; CONFIDENTIAL
    </div>
    """

    # Insert CSS before </head>
    html = html.replace('</head>', pdf_css + '</head>')

    # Insert cover page and header/footer content after <body>
    html = html.replace('<body>', f'<body>{header_footer}{cover}<div style="page-break-before:always;"></div>')

    return html


def render_lb_pdf(html_report: str) -> bytes:
    """Convert a rendered HTML report string to PDF bytes."""
    pdf_html = _prepare_html_for_pdf(html_report)

    buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(
        src=pdf_html,
        dest=buffer,
        encoding='utf-8',
    )

    if pisa_status.err:
        raise RuntimeError(f"PDF generation failed with {pisa_status.err} error(s)")

    return buffer.getvalue()
