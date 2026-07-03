"""
Enhanced IDOR Feature Engineering
Extracts richer features from IDOR scan data to improve model accuracy.
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs


# ─────────────────────────────────────────────────────────────────────────────
# Feature Extractors
# ─────────────────────────────────────────────────────────────────────────────

def get_url_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract URL-structure features."""
    df = df.copy()

    def _endpoint(row):
        try:
            return urlparse(str(row)).path
        except Exception:
            return ""

    def _param_key_count(param_str):
        try:
            return len(str(param_str).split("&"))
        except Exception:
            return 1

    def _param_type(param_str):
        try:
            val = str(param_str).split("=")[-1]
            if val.isdigit():
                return "numeric"
            if re.match(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", val):
                return "uuid"
            return "alphanumeric"
        except Exception:
            return "none"

    def _path_depth(url_str):
        try:
            path = urlparse(str(url_str)).path
            return len([p for p in path.split("/") if p])
        except Exception:
            return 0

    def _param_is_numeric(param_str):
        try:
            val = str(param_str).split("=")[-1]
            return int(val.isdigit())
        except Exception:
            return 0

    def _param_is_sequential(param_str):
        """Flag if the ID value looks like a low sequential integer (1–9999)."""
        try:
            val = str(param_str).split("=")[-1]
            if val.isdigit():
                return int(1 <= int(val) <= 9999)
            return 0
        except Exception:
            return 0

    df["endpoint_path"]    = df.get("endpoint", df.get("url", "")).apply(_endpoint)
    df["param_key_count"]  = df.get("parameter", df.get("url", "")).apply(_param_key_count)
    df["param_type_pattern"] = df.get("parameter", df.get("url", "")).apply(_param_type)
    df["path_depth"]       = df.get("url", df.get("endpoint", "")).apply(_path_depth)
    df["param_is_numeric"] = df.get("parameter", df.get("url", "")).apply(_param_is_numeric)
    df["param_is_sequential"] = df.get("parameter", df.get("url", "")).apply(_param_is_sequential)

    return df


def get_parameter_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract access-pattern features."""
    df = df.copy()

    # Self-access: is the requester accessing their own resource?
    if "user_id" in df.columns and "target_id" in df.columns:
        df["self_access"] = (df["user_id"].astype(str) == df["target_id"].astype(str)).astype(int)

        # Numeric ID delta between requester and target
        def _id_delta(row):
            try:
                return abs(int(str(row["target_id"])) - int(str(row["user_id"])))
            except (ValueError, TypeError):
                return -1

        df["param_delta"] = df.apply(_id_delta, axis=1)

        # Parameter change rate per user (how many unique targets each user hits)
        param_change = df.groupby("user_id")["target_id"].nunique().reset_index(name="unique_targets")
        total_reqs   = df.groupby("user_id").size().reset_index(name="total_requests")
        user_stats   = pd.merge(param_change, total_reqs, on="user_id")
        user_stats["param_change_rate"] = user_stats["unique_targets"] / user_stats["total_requests"]
        df = pd.merge(df, user_stats[["user_id", "param_change_rate"]], on="user_id", how="left")
    else:
        if "self_access" not in df.columns:
            df["self_access"] = 0
        if "param_delta" not in df.columns:
            df["param_delta"] = -1
        if "param_change_rate" not in df.columns:
            df["param_change_rate"] = 0.5

    return df


def get_response_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract HTTP response features."""
    df = df.copy()

    # Status code as category code
    if "status_code" in df.columns:
        df["status_code_cat"] = df["status_code"].astype("category").cat.codes
        df["status_is_200"]   = (df["status_code"] == 200).astype(int)
        df["status_is_403"]   = (df["status_code"] == 403).astype(int)
        df["status_is_404"]   = (df["status_code"] == 404).astype(int)
    else:
        df["status_code_cat"] = 0
        df["status_is_200"] = 0
        df["status_is_403"] = 0
        df["status_is_404"] = 0

    # Response size
    if "response_length" not in df.columns:
        df["response_length"] = 0

    # Large response = likely has data = potentially sensitive
    df["response_is_large"] = (df["response_length"] > 500).astype(int)

    return df


def get_auth_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract authentication-related features."""
    df = df.copy()

    SENSITIVE_KEYWORDS = [
        "email", "phone", "password", "address", "ssn",
        "credit_card", "account", "token", "secret", "api_key",
    ]

    def _has_sensitive(row):
        text = " ".join(str(v) for v in row.values if isinstance(v, str)).lower()
        return int(any(kw in text for kw in SENSITIVE_KEYWORDS))

    # Method type encoding
    if "method" in df.columns:
        df["is_get"]  = (df["method"].str.upper() == "GET").astype(int)
        df["is_post"] = (df["method"].str.upper() == "POST").astype(int)
    else:
        df["is_get"] = 1
        df["is_post"] = 0

    # Has authorization header
    if "headers" in df.columns:
        df["has_auth_header"] = df["headers"].apply(
            lambda h: int("authorization" in str(h).lower() or "cookie" in str(h).lower())
        )
    else:
        if "has_auth_header" not in df.columns:
            df["has_auth_header"] = 0

    # Sensitive data found in response
    if "sensitive_data_found" not in df.columns:
        df["sensitive_data_found"] = df.apply(_has_sensitive, axis=1)

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Full Pipeline
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_COLS = [
    "param_key_count",
    "param_is_numeric",
    "param_is_sequential",
    "param_delta",
    "path_depth",
    "self_access",
    "param_change_rate",
    "status_code_cat",
    "status_is_200",
    "status_is_403",
    "status_is_404",
    "response_length",
    "response_is_large",
    "sensitive_data_found",
    "is_get",
    "is_post",
    "has_auth_header",
    "is_unauthorized",  # label-adjacent; kept for supervised training
]


def run_feature_pipeline(df: pd.DataFrame) -> pd.DataFrame:
    """Apply all feature extractors and return the feature-ready dataframe."""
    df = get_url_features(df)
    df = get_parameter_features(df)
    df = get_response_features(df)
    df = get_auth_features(df)

    # Ensure all expected columns exist
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0

    return df[FEATURE_COLS]


def generate_summary_report(df: pd.DataFrame, output_path: str):
    """Write a markdown feature-engineering summary report."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True) if os.path.dirname(output_path) else None

    with open(output_path, "w") as f:
        f.write("# IDOR Feature Engineering Summary Report\n\n")
        f.write(f"- **Total Samples**: {len(df)}\n")
        if "is_unauthorized" in df.columns:
            unauth_pct = df["is_unauthorized"].mean() * 100
            f.write(f"- **Unauthorized Access Rate**: {unauth_pct:.1f}%\n")
        if "self_access" in df.columns:
            self_pct = df["self_access"].mean() * 100
            f.write(f"- **Self-Access Rate**: {self_pct:.1f}%\n\n")
        f.write("## Feature Columns\n\n")
        for col in FEATURE_COLS:
            if col in df.columns:
                f.write(f"- `{col}`: mean={df[col].mean():.3f}, std={df[col].std():.3f}\n")


# ─────────────────────────────────────────────────────────────────────────────
import os

def main():
    input_path  = "projects/auth_session/data/idor_dataset.csv"
    output_path = "projects/auth_session/data/idor_features_v2.csv"
    report_path = "projects/auth_session/docs/idor_feature_summary_v2.md"

    print(f"Loading dataset from {input_path} ...")
    df_raw = pd.read_csv(input_path)
    print(f"  Loaded {len(df_raw)} rows, {df_raw.shape[1]} columns.")

    df_features = run_feature_pipeline(df_raw)
    df_features.to_csv(output_path, index=False)
    print(f"Feature dataset saved → {output_path}")

    generate_summary_report(df_features, report_path)
    print(f"Summary report saved  → {report_path}")


if __name__ == "__main__":
    main()
