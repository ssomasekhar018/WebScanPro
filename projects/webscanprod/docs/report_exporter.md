# WebScanPro — Initial Report Exporter

This document describes an initial, runnable pipeline to export vulnerability data to polished HTML and PDF reports using ReportLab (PDF), Plotly (interactive charts), and Seaborn (statistical visualizations).

## Goal
- Generate visualizations from `findings.csv` using Seaborn and Plotly.
- Export a responsive HTML report (embedded Plotly and static images).
- Produce a printable PDF with text, tables, and chart images.
- Keep source data, images, and outputs reproducible and organized.

## Preconditions / Input
- Python 3.8+ recommended
- Packages: `pandas`, `numpy`, `matplotlib`, `seaborn`, `plotly`, `reportlab`, `jinja2`, `kaleido`
- Input: `projects/webscanprod/data/processed/findings.csv` with columns: `vuln_id, vuln_name, severity, affected_url, description, recommendation, status` (status optional)

Install:
```
pip install -r projects/webscanprod/requirements.txt
```

## Directory Layout
```
projects/webscanprod/
├── data/
│   └── processed/findings.csv
├── reports/
│   ├── html/
│   └── pdf/
├── assets/
│   └── images/  # generated chart PNGs
├── scripts/
│   ├── generate_visuals.py
│   ├── export_html.py
│   └── export_pdf.py
└── templates/
    └── report_template.html.j2
```

## Steps
1) Load & sanitize data (`scripts/generate_visuals.py`)
   - Normalize severity labels, drop missing IDs/names, default `status` if missing.
2) Generate visualizations
   - Seaborn bar plot of severity counts → `assets/images/severity_counts.png`
   - Plotly treemap interactive → `reports/html/treemap.html` and static `assets/images/treemap.png`
3) Build HTML report (`scripts/export_html.py`)
   - Renders Jinja2 template with summary, inline Plotly div, static image, and findings table.
4) Build PDF report (`scripts/export_pdf.py`)
   - Uses ReportLab to draw summary and embed static images; lists findings.

## Run
```
python projects/webscanprod/scripts/generate_visuals.py
python projects/webscanprod/scripts/export_html.py
python projects/webscanprod/scripts/export_pdf.py
```

## Deliverables
- `reports/html/report_<date>.html` (e.g., `report_20251112_0632UTC.html`)
- `reports/html/treemap.html`
- `reports/pdf/report_<date>.pdf` (e.g., `report_20251112_0631UTC.pdf`)
- `assets/images/severity_counts.png`
- `assets/images/treemap.png`

## Validation Checklist
- [ ] Charts generated and saved under `assets/images/`
- [ ] Interactive treemap saved to `reports/html/treemap.html`
- [ ] HTML report renders with summary, chart, and findings table
- [ ] PDF report generated with readable content and images
- [ ] Counts in reports match dataset totals
