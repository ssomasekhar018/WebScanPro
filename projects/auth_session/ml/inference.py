#!/usr/bin/env python3
"""
Inference utilities for Authentication & Session Security models.

Loads trained scaler and models (Isolation Forest, One-Class SVM if available),
prepares feature vectors to match training, and returns anomaly predictions/scores.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
AUTH_DIR = os.path.join(BASE_DIR, "projects", "auth_session")
DATA_DIR = os.path.join(AUTH_DIR, "data")
ML_DIR = os.path.join(AUTH_DIR, "ml")
LOGS_DIR = os.path.join(AUTH_DIR, "logs")

FEATURE_DATASET = os.path.join(DATA_DIR, "feature_dataset.csv")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")
IF_PATH = os.path.join(ML_DIR, "isolation_forest_model.pkl")
OCSVM_PATH = os.path.join(ML_DIR, "oneclass_svm_model.pkl")
AE_PATH = os.path.join(ML_DIR, "autoencoder_model_fixed.h5")

os.makedirs(LOGS_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(LOGS_DIR, f"inference_{timestamp}.log")


def log(msg: str):
    ts = datetime.now().isoformat()
    line = f"[{ts}] {msg}"
    print(line)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _load_feature_columns() -> list[str]:
    """Derive feature columns from training dataset (exclude IDs/labels)."""
    df = pd.read_csv(FEATURE_DATASET, nrows=5)
    exclude = {
        "event_id", "timestamp", "username_anon", "ip_address_anon",
        "is_anomalous", "is_bruteforce_candidate", "auth_result"
    }
    feature_cols = [c for c in df.columns if c not in exclude]
    # Keep only numeric columns
    num_cols = [c for c in feature_cols if pd.api.types.is_numeric_dtype(df[c])]
    return num_cols


class InferenceEngine:
    def __init__(self):
        self.scaler = joblib.load(SCALER_PATH)
        self.feature_columns = _load_feature_columns()

        self.iso_forest = joblib.load(IF_PATH) if os.path.exists(IF_PATH) else None
        self.oneclass_svm = joblib.load(OCSVM_PATH) if os.path.exists(OCSVM_PATH) else None

        # Autoencoder optional
        self.autoencoder = None
        try:
            import tensorflow as tf  # noqa: F401
            if os.path.exists(AE_PATH):
                from tensorflow.keras.models import load_model
                self.autoencoder = load_model(AE_PATH)
        except Exception:
            self.autoencoder = None

        log(
            "Loaded models: "
            f"IF={'yes' if self.iso_forest else 'no'}, "
            f"OCSVM={'yes' if self.oneclass_svm else 'no'}, "
            f"AE={'yes' if self.autoencoder is not None else 'no'}"
        )

    def _prepare_X(self, df: pd.DataFrame) -> np.ndarray:
        # Ensure all feature columns exist; missing -> 0, extra -> ignored
        X = pd.DataFrame(columns=self.feature_columns)
        for col in self.feature_columns:
            X[col] = df.get(col, 0)
        X = X.fillna(0)
        return self.scaler.transform(X.values)

    def predict(self, df: pd.DataFrame) -> dict:
        """Return predictions and scores from available models and an ensemble."""
        X_scaled = self._prepare_X(df)
        results = {}

        # Isolation Forest
        if self.iso_forest is not None:
            pred_if = (self.iso_forest.predict(X_scaled) == -1).astype(int)
            score_if = -self.iso_forest.score_samples(X_scaled)
            results["isolation_forest"] = {
                "pred": pred_if.tolist(),
                "score": score_if.tolist(),
            }

        # One-Class SVM
        if self.oneclass_svm is not None:
            pred_oc = (self.oneclass_svm.predict(X_scaled) == -1).astype(int)
            score_oc = -self.oneclass_svm.decision_function(X_scaled)
            results["oneclass_svm"] = {
                "pred": pred_oc.tolist(),
                "score": score_oc.tolist(),
            }

        # Autoencoder (optional)
        if self.autoencoder is not None:
            recon = self.autoencoder.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - recon, 2), axis=1)
            # Threshold choice should be persisted; fallback to 95th percentile of last training normal would be better.
            # Here we use a percentile on current batch as a conservative placeholder.
            threshold = float(np.percentile(mse, 95))
            pred_ae = (mse > threshold).astype(int)
            results["autoencoder"] = {
                "pred": pred_ae.tolist(),
                "score": mse.tolist(),
                "threshold": threshold,
            }

        # Ensemble: max across available predictors
        if results:
            preds = []
            for i in range(len(df)):
                votes = []
                for m in results.values():
                    votes.append(m["pred"][i])
                preds.append(int(max(votes) if votes else 0))
            results["ensemble"] = {"pred": preds}

        return results


def main():
    # Basic smoke test using tail of dataset
    engine = InferenceEngine()
    df = pd.read_csv(FEATURE_DATASET)
    if "is_anomalous" in df.columns:
        df = df.drop(columns=["is_anomalous"])  # inference won't include label
    sample = df.tail(5).reset_index(drop=True)
    out = engine.predict(sample)
    log("Sample inference: " + json.dumps({k: {"pred_len": len(v.get("pred", []))} for k, v in out.items()}))


if __name__ == "__main__":
    main()


