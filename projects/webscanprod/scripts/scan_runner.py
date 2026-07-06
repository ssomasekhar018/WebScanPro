import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd


def webscanprod_root() -> Path:
    # scripts/ is one level under the project root
    return Path(__file__).resolve().parent.parent


BASE_DIR = webscanprod_root()
RAW_DIR = BASE_DIR / "data" / "raw_findings"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
OUTPUT_CSV = PROCESSED_DIR / "findings.csv"


SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def normalize_severity(value: Any) -> str:
    if value is None:
        return "Low"
    s = str(value).strip().lower()
    return SEVERITY_MAP.get(s, s.capitalize() if s else "Low")


def normalize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "vuln_id": rec.get("vuln_id") or rec.get("id") or rec.get("vulnerability_id") or "",
        "vuln_name": rec.get("vuln_name") or rec.get("name") or rec.get("title") or "",
        "description": rec.get("description") or rec.get("details") or "",
        "severity": normalize_severity(rec.get("severity")),
        "affected_url": rec.get("affected_url") or rec.get("url") or rec.get("endpoint") or "",
        "impact": rec.get("impact") or rec.get("risk") or "",
        "recommendation": rec.get("recommendation") or rec.get("mitigation") or rec.get("fix") or "",
    }


def parse_json_file(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    findings = []
    if isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            findings = data["findings"]
        else:
            # Attempt to treat the dict as a single record
            findings = [data]
    elif isinstance(data, list):
        findings = data
    return [normalize_record(rec) for rec in findings]


def parse_csv_file(path: Path) -> List[Dict[str, Any]]:
    df = pd.read_csv(path)
    records = []
    for _, row in df.iterrows():
        rec = {k: row.get(k) for k in df.columns}
        records.append(normalize_record(rec))
    return records


def parse_xml_file(path: Path) -> List[Dict[str, Any]]:
    tree = ET.parse(path)
    root = tree.getroot()
    records = []
    # Expected structure: <findings><finding>...</finding></findings>
    for finding in root.findall(".//finding"):
        rec = {
            "vuln_id": (finding.findtext("vuln_id") or finding.findtext("id") or ""),
            "vuln_name": (finding.findtext("vuln_name") or finding.findtext("name") or ""),
            "description": (finding.findtext("description") or ""),
            "severity": (finding.findtext("severity") or ""),
            "affected_url": (finding.findtext("affected_url") or finding.findtext("url") or ""),
            "impact": (finding.findtext("impact") or finding.findtext("risk") or ""),
            "recommendation": (finding.findtext("recommendation") or finding.findtext("mitigation") or ""),
        }
        records.append(normalize_record(rec))
    return records


def collect_findings() -> List[Dict[str, Any]]:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    all_records: List[Dict[str, Any]] = []
    for path in sorted(RAW_DIR.glob("*")):
        if path.suffix.lower() == ".json":
            recs = parse_json_file(path)
        elif path.suffix.lower() == ".csv":
            recs = parse_csv_file(path)
        elif path.suffix.lower() in {".xml"}:
            recs = parse_xml_file(path)
        else:
            print(f"Skipping unsupported file: {path.name}")
            recs = []
        if recs:
            print(f"Parsed {len(recs)} records from {path.name}")
            all_records.extend(recs)

    return all_records


def main():
    records = collect_findings()
    if not records:
        print("No findings parsed. Ensure files exist in data/raw_findings/")
        # Still create an empty CSV with headers
        df = pd.DataFrame(columns=[
            "vuln_id", "vuln_name", "description", "severity",
            "affected_url", "impact", "recommendation",
        ])
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"Saved empty dataset to {OUTPUT_CSV}")
        return

    df = pd.DataFrame.from_records(records)
    # Basic cleanup
    df.fillna("", inplace=True)
    df["severity"] = df["severity"].apply(normalize_severity)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved {len(df)} records to {OUTPUT_CSV}")
    # Severity summary
    summary = df["severity"].value_counts().to_dict()
    print("Severity summary:", summary)


if __name__ == "__main__":
    main()

