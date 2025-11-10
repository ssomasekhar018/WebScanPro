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
    f["html_content_length"] = df["html_len"]
    f["error_message_flag"] = df["error_flag"]
    f["content_length_delta"] = df["reflected_flag"]

    return f


def get_preprocessor() -> StandardScaler:
    return StandardScaler()