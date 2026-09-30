# Usage guide

A step-by-step walkthrough of producing a customer report. Screenshots live in
[`screenshots/`](screenshots/) — see that folder's README for what to capture.

## 1. Launch

```bash
streamlit run app.py --server.port 8501
```
Open **http://localhost:8501**.

![Landing page](screenshots/01-landing.png)

## 2. Upload an export

Use the sidebar uploader to select a Security Auditor JSON export. To explore
without your own data, upload the bundled **`input/security-audit.sample.json`**
(anonymized demo).

The parser validates the file — if it's missing required keys (`tenant`,
`namespaces`, `summary`, `findings`) you'll get a clear error.

## 3. Set customer entitlements

In the sidebar, untick any product the customer has **not** purchased (Bot
Defense, API Protection, Client-Side Defense, MUD, Rate Limiting, …). Findings
for unpurchased products are then reframed as **Additional Opportunities**
rather than counted as failures.

![Entitlements](screenshots/02-entitlements.png)

## 4. Read the dashboard

The dashboard shows the overall security score, a severity breakdown, and a
per-Load-Balancer table. Use it to spot the worst-off Load Balancers, then open
one for detail.

![Dashboard](screenshots/03-dashboard.png)

## 5. Work a Load Balancer report

Findings are grouped into tabs: **High / Medium / Low** first (actionable
REVIEW/CAUTION items only), then **category** tabs (TLS, Origin Pools, WAF,
**Malware Detection**, **Malicious User Detection (MUD)**, etc.).

Expand a finding and you can:

- **Edit the message** — the text box is internal-only; an edited row is marked
  with ✏️ in the app, but the customer-facing export shows only the clean edited
  text.
- **Override status / severity** — two dropdowns let you re-classify a finding
  (e.g. High→Medium, or REVIEW→CAUTION). It immediately moves to the matching
  tab and every count updates. `Auto` reverts to the original; overridden rows
  show 🔧. Clear everything with **Reset all overrides** in the sidebar.
- **Exclude the finding** — untick the checkbox on the right to drop it from the
  report. Totals recalculate automatically.

![LB report tabs](screenshots/04-lb-report.png)

## 6. Fill the manual checklist

Complete the manual items the auditor can't detect (status dropdown + notes).
These are available on **both** the **Namespace Report** and each Load
Balancer's **Tenant-Wide Context** tab, and they're **connected** — editing an
item in one place updates it everywhere and flows into every export.

![Manual checklist](screenshots/05-manual-checklist.png)

## 7. Generate & download

Scroll to the **Generate & Download Report** section at the bottom of a Load
Balancer report and click **🔄 Generate / Refresh Report**. The report is built
only when you click (so toggling checkboxes stays fast) and always reflects your
latest edits, exclusions, and overrides. Then download:

- **HTML** — self-contained, good for email.
- **PDF** — F5-branded cover, headers/footers, portrait A4.
- **Word (.docx)** — best-practice guide with ☐ checkboxes.

If you change anything afterwards, click **Generate** again to refresh.

From the Namespace Report you can also export the namespace-wide report and the
combined Word guide. The **Security Review Checklist** (generic, no tenant data)
is the one to share with a customer for self-verification.

![Downloads](screenshots/06-downloads.png)

## Status meaning quick reference

| Label | Underlying | Color | Action |
|---|---|---|---|
| REVIEW | FAIL | red | Remediate |
| CAUTION | WARN | orange | Review |
| PASS | PASS | green | None |
| INFO / SKIP | INFO / SKIP | neutral | Informational |
