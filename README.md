# XC Security Report Generator

A **Streamlit** app that turns an **F5 Distributed Cloud (XC) Security Auditor**
JSON export into clean, customer-facing **Security Posture Review (SPR)**
reports. Upload a raw audit export and get an interactive dashboard plus
downloadable **HTML**, **PDF**, and **Word** reports — including a blank
"best practice checklist" you can hand to a customer for self-verification.

> Internal F5 tool. Do **not** commit real customer audit exports — see
> [Security & customer data](#-security--customer-data).

---

## Table of contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Usage walkthrough](#usage-walkthrough)
- [Reports & exports](#reports--exports)
- [Understanding the report](#understanding-the-report)
- [Customizing](#customizing)
- [Security & customer data](#-security--customer-data)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Contributing / pushing changes](#contributing--pushing-changes)
- [More docs](#more-docs)

---

## What it does

- **Parses** the XC Security Auditor v2 JSON (categorized rule IDs like
  `WAF-01`, `TLS-03`, `OP-03`, `SP-01`, …).
- **Links** every finding to the Load Balancer it belongs to, and rolls
  tenant-wide items into a namespace report.
- **Presents** results as an interactive dashboard with per-Load-Balancer
  drill-downs organized into severity and category tabs.
- **Lets the reviewer edit** finding messages and **exclude** findings before
  export — metrics update live.
- **Exports** self-contained **HTML**, a print-ready **PDF** (F5-branded cover,
  headers/footers), and an editable **Word** best-practice guide / checklist.

## Quick start

Prerequisites: **Python 3.11+** (tested on 3.14) and `pip`.

**Windows (PowerShell):**
```powershell
git clone https://github.com/s-aktar_f5inc/xc-security-report.git
cd xc-security-report
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py --server.port 8501
```

**macOS / Linux:**
```bash
git clone https://github.com/s-aktar_f5inc/xc-security-report.git
cd xc-security-report
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py --server.port 8501
```

Then open **http://localhost:8501**. Upload your own Security Auditor JSON in
the sidebar, or try the included **`input/security-audit.sample.json`**
(fully anonymized demo data) to explore immediately.

## Usage walkthrough

1. **Upload** a Security Auditor JSON export via the sidebar uploader.
2. **Set customer entitlements** (sidebar) — untick any product the customer
   didn't purchase (Bot Defense, API Protection, etc.) so unpurchased features
   are reframed as *opportunities* instead of failures.
3. **Review the Dashboard** — overall security score, severity breakdown, and a
   per-Load-Balancer table. Click a Load Balancer to open its full report.
4. **Work through a Load Balancer report** — findings are grouped into tabs
   (High / Medium / Low, then per-category tabs like TLS, Origin Pools, WAF…).
   For each finding you can:
   - **Edit** the message text (internal only; the customer-facing export shows
     the clean edited text).
   - **Exclude** it using the checkbox on the right — excluded findings drop out
     of the report and the totals adjust automatically.
5. **Fill the manual checklist** (Namespace Report page) for items the auditor
   can't detect (e.g. console IP restriction).
6. **Download** the report in the format you need (HTML / PDF / Word).

## Reports & exports

| Format | Best for | Notes |
|---|---|---|
| **HTML** | Emailing a self-contained interactive report | Single file, no dependencies |
| **PDF** | Formal / print delivery | F5-branded cover page, page headers/footers, portrait A4 |
| **Word (.docx)** | A checklist the **customer fills in themselves** | Printable ☐ checkboxes per control |

Two Word variants are produced by `docx_export.py`:
- **Best Practice Guide** — generic checklist **plus** a per-report appendix
  with your tenant's actual findings.
- **Security Review Checklist** — generic-only, no tenant data: the full list
  of controls we check per Load Balancer, with blank checkboxes, so a customer
  can self-verify. Ideal to share externally.

## Understanding the report

**Status labels** (customer-facing wording; underlying auditor values in
parentheses):

| Label | Color | Meaning |
|---|---|---|
| **REVIEW** *(FAIL)* | red | Needs attention / remediation |
| **CAUTION** *(WARN)* | orange | Worth reviewing |
| **PASS** | green | Control satisfied |
| **INFO / SKIP** | grey/blue | Informational or not applicable |

- **Severity tabs** (High/Medium/Low) contain only actionable findings
  (REVIEW/CAUTION). PASS/INFO/SKIP live in their category or baseline tabs.
- **Category tabs** (TLS, Certificates, Origin Pools, Health Check, WAF
  Configuration, WAF Policy Details, Bot, API, Malware, DDoS, Client-Side
  Defense, Service Policies, Rate Limiting, …) group everything for that area.
- **Additional Opportunities** surfaces findings for unpurchased products in a
  softer framing, kept out of the customer-facing severity counts.

## Customizing

- **Change a rule's severity** — add an entry to `_SEVERITY_OVERRIDES` in
  `finding_corrections.py`. Example already in place:
  ```python
  _SEVERITY_OVERRIDES = {
      "SP-01": "MEDIUM",   # Service Policy No Allow-All: High -> Medium
  }
  ```
- **Fix a broken reference URL** — add to `_URL_REPLACEMENTS` in the same file.
- **Adjust product entitlements** — edit the `PRODUCTS` list in
  `product_entitlements.py`.
- **Tune the manual checklist** — edit `MANUAL_CHECKLIST_ITEMS` in
  `manual_checklist.py`.
- **Restyle HTML/PDF** — CSS lives in `html_export.py`; PDF cover/scaffold in
  `pdf_export.py`.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full picture.

## 🔒 Security & customer data

**Never commit real Security Auditor exports.** They contain customer tenant
names, Load Balancer names, hostnames, and IPs.

- `.gitignore` excludes `input/*.json` **except** the anonymized
  `input/security-audit.sample.json`.
- Generated `*.pdf` / `*.docx` / `*.html` outputs and the `uploads/` /
  `generated_reports/` folders are also ignored.
- To refresh the sample from a real export, anonymize it first (map
  tenant/LB/object names to synthetic values and scrub IPs/emails) before it
  goes anywhere near git. See `docs/ARCHITECTURE.md` for the approach used.

## Project layout

```
app.py                 Streamlit UI (dashboard, per-LB report, namespace report)
parser.py              Raw JSON -> AuditSummary + List[Finding]
models.py              Dataclasses: Finding, AuditSummary, LoadBalancerReport, NamespaceReport
relationship.py        Findings -> {lb_name: LoadBalancerReport} + NamespaceReport
report_data.py         Model objects -> display dicts; status colors/labels, severity grouping
finding_corrections.py Post-parse corrections: URL fixes, severity overrides, TLS blindfold
policy_type.py         Service-policy type heuristics & applicability
product_entitlements.py Purchased-product gating (Bot Defense, API, CSD, …)
manual_checklist.py    Items the auditor can't auto-detect
html_export.py         Self-contained HTML report generation
pdf_export.py          HTML -> PDF (xhtml2pdf) with F5 cover, headers/footers
docx_export.py         Word best-practice guide + customer checklist
main.py                CLI sanity check (parse + relationships, print summary)
analyzer.py            CLI scratch tool for inspecting a JSON export
assets/                F5 logo used on the PDF cover
input/                 Sample export (anonymized); real exports are gitignored
docs/                  Architecture, usage, screenshots
legacy_flask/          Original Flask prototype (reference only)
```

## Troubleshooting

- **`ModuleNotFoundError`** — activate the venv and re-run
  `pip install -r requirements.txt`.
- **Port 8501 already in use** — run on another port:
  `streamlit run app.py --server.port 8502`.
- **PDF generation fails / weird spacing** — this app uses **xhtml2pdf**
  (pure Python) specifically because **WeasyPrint doesn't work on Windows**
  (needs GTK/Pango). Stick with xhtml2pdf. It's picky about CSS —
  `pdf_export.py` already strips `width:100%` and converts CSS grids to tables.
- **"This doesn't look like a Security Auditor export"** — the JSON is missing
  required top-level keys (`tenant`, `namespaces`, `summary`, `findings`).
  Make sure it's a v2 auditor export.
- **Edited text or exclusions look mismatched after deleting items** — fixed;
  widgets are keyed by stable finding IDs. If you see it, re-upload the JSON to
  clear stale session state.

## Contributing / pushing changes

Everyday git loop after the repo exists:
```bash
git status                 # see what changed
git add .                  # stage (respects .gitignore)
git commit -m "Describe your change"
git push
```
For a shared repo, prefer a branch + Pull Request per change:
```bash
git checkout -b my-change
git add . && git commit -m "..."
git push -u origin my-change   # then open a PR on GitHub
```
Colleagues get your updates with `git pull`. Full guidance in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## More docs

- [`docs/USAGE.md`](docs/USAGE.md) — detailed, screenshot-driven walkthrough
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — data flow, module
  responsibilities, relationship-linking design
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup and how to extend
