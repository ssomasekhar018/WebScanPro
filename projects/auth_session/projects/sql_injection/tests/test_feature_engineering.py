# projects/sql_injection/tests/test_feature_engineering.py
import pandas as pd
import pytest
from projects.sql_injection.scripts.feature_engineering import extract_features

@pytest.fixture
def sample_df():
    data = {
        "payload": ["' OR 1=1 --", "normal"],
        "url": ["http://example.com/login", "http://example.com/home"],
        "response_time": [0.15, 0.09],
        "status_code": [200, 200],
        "html_len": [3200, 1800],
        "error_flag": [0, 0],
        "reflected_flag": [1, 0],
    }
    return pd.DataFrame(data)

def test_feature_shape(sample_df):
    feats = extract_features(sample_df)
    assert feats.shape[0] == 2
    assert "payload_len" in feats.columns
    assert "has_sql_keywords" in feats.columns
    assert feats["payload_len"].iloc[0] == len("' OR 1=1 --")