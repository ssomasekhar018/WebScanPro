# WebScanProd — Vulnerability Assessment & Mitigation Report System

WebScanProd converts raw scanner outputs into standardized, auditable reports for developers and security teams. It parses raw findings, normalizes fields, categorizes by severity, and produces Markdown, PDF, and DOCX reports.

## Structure

projects/webscanprod/
- data/
  - raw_findings/
  - processed/findings.csv (generated)
- reports/
  - webscan_summary.md (generated)
  - vulnerability_report.pdf (generated)
  - vulnerability_report.docx (generated)
- scripts/
  - scan_runner.py
  - report_generator.py
- requirements.txt

## Prerequisites
- Python 3.9+
- Packages: pandas, reportlab, python-docx

Install dependencies:

```
pip install -r projects/webscanprod/requirements.txt
```

## Usage
1) Place raw scan files (JSON, CSV, or XML) into `projects/webscanprod/data/raw_findings/`.
2) Parse findings and generate processed dataset:

```
python projects/webscanprod/scripts/scan_runner.py
```

3) Generate reports (Markdown, PDF, DOCX):

```
python projects/webscanprod/scripts/report_generator.py
```

Outputs will be written to `projects/webscanprod/reports/`.

## Input Schema (normalized)
- vuln_id
- vuln_name
- description
- severity (Critical/High/Medium/Low)
- affected_url
- impact
- recommendation

## Notes
- The parser supports JSON lists or `{ "findings": [...] }` JSON structures, CSVs with matching columns, and simple XML with `<findings><finding>...</finding></findings>`.
- Directories are created if missing.
