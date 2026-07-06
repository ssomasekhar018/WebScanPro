from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import pandas as pd


def root() -> Path:
    return Path(__file__).resolve().parent.parent


BASE = root()
CSV_PATH = BASE / "data" / "processed" / "findings.csv"
TEMPLATES_DIR = BASE / "templates"
REPORTS_HTML_DIR = BASE / "reports" / "html"
ASSETS_IMG_DIR = BASE / "assets" / "images"


def render_html(df: pd.DataFrame, plotly_div: str, img_path: Path, out_html: Path):
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    tmpl = env.get_template('report_template.html.j2')
    counts = df['severity'].value_counts().to_dict() if len(df) else {}
    # Normalize image path for HTML (use forward slashes)
    img_rel = Path(img_path.relative_to(BASE)).as_posix()
    html = tmpl.render(
        project_name='WebScanProd Vulnerability Report',
        date=pd.Timestamp.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        total=len(df),
        counts=counts,
        plotly_div=plotly_div,
        img_path=img_rel,
        findings=df.to_dict(orient='records'),
    )
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html, encoding='utf-8')


def main():
    if not CSV_PATH.exists():
        print(f"Processed findings not found: {CSV_PATH}")
        return
    df = pd.read_csv(CSV_PATH)
    inline_path = REPORTS_HTML_DIR / "treemap_inline.html"
    if inline_path.exists():
        plotly_div = inline_path.read_text(encoding='utf-8')
    else:
        # Fallback: minimal plotly div from data
        try:
            import plotly.express as px
            fig = px.treemap(df, path=['severity', 'vuln_name'], values=None,
                             title='Vulnerabilities Treemap (by severity)')
            plotly_div = fig.to_html(include_plotlyjs='cdn', full_html=False)
        except Exception:
            plotly_div = "<p>Plotly chart unavailable.</p>"

    img_path = ASSETS_IMG_DIR / "severity_counts.png"
    date_str = pd.Timestamp.utcnow().strftime('%Y%m%d_%H%MUTC')
    out_html = REPORTS_HTML_DIR / f"report_{date_str}.html"
    render_html(df, plotly_div, img_path, out_html)
    print(f"Wrote HTML report: {out_html}")


if __name__ == "__main__":
    main()
