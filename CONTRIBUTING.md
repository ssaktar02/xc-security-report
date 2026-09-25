# Contributing

Internal guide for developing and extending the XC Security Report Generator.

## Dev setup

```bash
python -m venv venv
# Windows:  .\venv\Scripts\Activate.ps1
# Unix:     source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py --server.port 8501
```

Quick non-UI sanity check (parses + builds relationships, prints a summary):
```bash
python main.py input/security-audit.sample.json
```

## Codebase orientation

Data flows in one direction:

```
JSON export
  -> parser.py            (AuditSummary + List[Finding])
  -> finding_corrections  (URL fixes, severity overrides, TLS blindfold)
  -> relationship.py      ({lb_name: LoadBalancerReport}, NamespaceReport)
  -> report_data.py       (display dicts, grouping, colors/labels)
  -> app.py / *_export.py (UI + HTML / PDF / Word)
```

Keep this direction. Corrections happen **once**, right after parsing, so every
downstream view (dashboard, exports, health score) sees the same picture.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Common changes

### Override a rule's severity
`finding_corrections.py`:
```python
_SEVERITY_OVERRIDES = {
    "SP-01": "MEDIUM",
    # "TLS-03": "HIGH",
}
```

### Fix a broken reference URL
Add to `_URL_REPLACEMENTS` in `finding_corrections.py`.

### Add / change a status display label
`report_data.py` — `STATUS_DISPLAY_LABELS` (e.g. `FAIL -> REVIEW`,
`WARN -> CAUTION`). This is the single source of truth used by the UI and all
exports.

### Add a product entitlement
`product_entitlements.py` — extend the `PRODUCTS` list and its rule mapping.

### Add a manual checklist item
`manual_checklist.py` — append a `ManualChecklistItem` to
`MANUAL_CHECKLIST_ITEMS`.

### Move a rule to a different report tab
Tab membership is defined in `app.py` (`_STANDALONE_TAB_RULES`,
`_INFORMATIONAL_RULES`) and mirrored in `html_export.py`. Update **both** so the
app and the HTML/PDF exports stay consistent.

## Gotchas

- **Streamlit widget keys must be stable**, not index-based. Findings tables key
  widgets by `rule_id::object_name` (plus an occurrence counter) so edits and
  exclusions don't shift onto the wrong finding when the list re-orders.
- **PDF = xhtml2pdf only.** WeasyPrint needs GTK/Pango and does not work on
  Windows. xhtml2pdf is picky: no `width:100%` in tables, no
  `display:table-cell`, no full-page background divs. `pdf_export.py` already
  works around these.
- **Never commit real customer JSON.** Only the anonymized
  `input/security-audit.sample.json` is tracked.

## Validating a change

There is no automated test suite yet. Before pushing, at minimum:

```bash
# 1. Byte-compile everything
python -c "import py_compile,glob; [py_compile.compile(f,doraise=True) for f in glob.glob('*.py')]"

# 2. Parse + build against the sample
python main.py input/security-audit.sample.json

# 3. Smoke-test the app in the browser (upload the sample, open an LB report,
#    download HTML/PDF/Word)
```

## Git workflow

```bash
git checkout -b my-change
git add .                       # respects .gitignore
git commit -m "Describe the change"
git push -u origin my-change    # then open a Pull Request
```

Commit messages: short imperative summary (e.g. "Change SP-01 severity to
Medium"). Prefer a branch + PR over committing straight to `main` so changes can
be reviewed.
