from pathlib import Path
from typing import Tuple
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px


def root() -> Path:
    return Path(__file__).resolve().parent.parent


BASE = root()
CSV_PATH = BASE / "data" / "processed" / "findings.csv"
ASSETS_IMG_DIR = BASE / "assets" / "images"
REPORTS_HTML_DIR = BASE / "reports" / "html"


def load_and_clean(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "severity" in df.columns:
        df["severity"] = df["severity"].astype(str).str.title().fillna("Info")
    else:
        df["severity"] = "Info"
    if "vuln_id" in df.columns and "vuln_name" in df.columns:
        df = df.dropna(subset=["vuln_id", "vuln_name"])
    # default status if missing
    if "status" not in df.columns:
        df["status"] = "Open"
    return df


def plot_severity_counts(df: pd.DataFrame, out_path: Path) -> None:
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    plt.figure(figsize=(6, 4))
    sns.barplot(data=counts, x="severity", y="count")
    plt.title("Vulnerabilities by Severity")
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path)
    plt.close()


def plot_treemap(df: pd.DataFrame, out_html: Path, out_png: Path) -> Tuple[str, Path, Path]:
    fig = px.treemap(df, path=["severity", "vuln_name"], values=None,
                     title="Vulnerabilities Treemap (by severity)")
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_png.parent.mkdir(parents=True, exist_ok=True)
    # Interactive HTML snippet
    fig.write_html(out_html, include_plotlyjs='cdn', full_html=True)
    # Static image for PDF
    fig.write_image(out_png, scale=2)
    # Inline snippet for Jinja2 embedding
    inline_div = fig.to_html(include_plotlyjs=False, full_html=False)
    return inline_div, out_html, out_png


def main():
    if not CSV_PATH.exists():
        print(f"Processed findings not found: {CSV_PATH}")
        return
    df = load_and_clean(CSV_PATH)
    print(f"Loaded dataset: {df.shape}")

    severity_img = ASSETS_IMG_DIR / "severity_counts.png"
    plot_severity_counts(df, severity_img)
    print(f"Saved severity barplot: {severity_img}")

    treemap_html = REPORTS_HTML_DIR / "treemap.html"
    treemap_png = ASSETS_IMG_DIR / "treemap.png"
    inline_div, _, _ = plot_treemap(df, treemap_html, treemap_png)
    inline_path = REPORTS_HTML_DIR / "treemap_inline.html"
    inline_path.parent.mkdir(parents=True, exist_ok=True)
    inline_path.write_text(inline_div, encoding="utf-8")
    print(f"Saved treemap HTML: {treemap_html}")
    print(f"Saved treemap PNG: {treemap_png}")
    print(f"Saved inline Plotly div: {inline_path}")


if __name__ == "__main__":
    main()

