# projects/sql_injection/scripts/feature_engineering.py
import pandas as pd
import re
from sklearn.preprocessing import StandardScaler

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    f = pd.DataFrame(index=df.index)

    # numeric
    f["url_len"] = df["url"].str.len()
    f["payload_len"] = df["payload"].str.len()
    f["response_time"] = df["response_time"]
    f["status_code"] = df["status_code"]
    f["html_len"] = df["html_len"]
    f["error_flag"] = df["error_flag"]
    f["reflected_flag"] = df["reflected_flag"]

    # SQL-keyword presence
    sql_keywords = ["select", "union", "insert", "delete", "drop", "alter", "--", ";", "/*", "*/"]
    f["has_sql_keywords"] = df["payload"].str.lower().apply(
        lambda x: int(any(k in x for k in sql_keywords))
    )

    # special-char density
    f["special_char_ratio"] = df["payload"].str.count(r"[;'\"\\-]").fillna(0) / (df["payload"].str.len() + 1)

    # payload entropy (simple)
    import math
    from collections import Counter
    def entropy(s):
        cnt = Counter(s)
        length = len(s) or 1
        return -sum(p * math.log2(p) for p in (c/length for c in cnt.values() if c))
    f["payload_entropy"] = df["payload"].apply(entropy)

    return f


def get_preprocessor() -> StandardScaler:
    return StandardScaler()