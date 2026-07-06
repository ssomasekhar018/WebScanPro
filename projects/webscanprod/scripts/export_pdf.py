from pathlib import Path
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, PageBreak
from reportlab.lib.styles import getSampleStyleSheet


def root() -> Path:
    return Path(__file__).resolve().parent.parent


BASE = root()
CSV_PATH = BASE / "data" / "processed" / "findings.csv"
REPORTS_PDF_DIR = BASE / "reports" / "pdf"
ASSETS_IMG_DIR = BASE / "assets" / "images"


def build_pdf(df: pd.DataFrame, image_paths: list[Path], out_pdf: Path):
    REPORTS_PDF_DIR.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(out_pdf), pagesize=A4)
    story = []

    # Title page
    story.append(Paragraph('WebScanProd Vulnerability Report', styles['Title']))
    story.append(Paragraph('Date: ' + pd.Timestamp.utcnow().strftime('%Y-%m-%d %H:%M UTC'), styles['Normal']))
    story.append(Spacer(1, 18))

    # Summary table
    counts = df['severity'].value_counts()
    data = [['Severity', 'Count']] + [[k, int(v)] for k, v in counts.items()]
    story.append(Table(data))
    story.append(Spacer(1, 12))

    # Add images (charts)
    for img in image_paths:
        if Path(img).exists():
            story.append(Image(str(img), width=450, height=250))
            story.append(Spacer(1, 12))

    # Findings table (first 20 rows)
    table_data = [['ID', 'Name', 'Severity', 'URL']]
    for _, r in df.head(20).iterrows():
        table_data.append([
            str(r.get('vuln_id', '')),
            str(r.get('vuln_name', ''))[:40],
            str(r.get('severity', '')),
            str(r.get('affected_url', ''))[:60],
        ])
    story.append(Table(table_data, repeatRows=1))

    # Optional page break for any appendix or extended content
    # story.append(PageBreak())

    doc.build(story)


def main():
    if not CSV_PATH.exists():
        print(f"Processed findings not found: {CSV_PATH}")
        return
    df = pd.read_csv(CSV_PATH)
    date_str = pd.Timestamp.utcnow().strftime('%Y%m%d_%H%MUTC')
    pdf_path = REPORTS_PDF_DIR / f"report_{date_str}.pdf"
    images = [ASSETS_IMG_DIR / "severity_counts.png", ASSETS_IMG_DIR / "treemap.png"]
    build_pdf(df, images, pdf_path)
    print(f"Wrote PDF report: {pdf_path}")


if __name__ == "__main__":
    main()
