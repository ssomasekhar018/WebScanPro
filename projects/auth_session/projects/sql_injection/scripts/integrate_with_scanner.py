# projects/sql_injection/scripts/integrate_with_scanner.py
import joblib
import logging
import pandas as pd
from pathlib import Path

from projects.sql_injection.scripts.feature_engineering import extract_features

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]          # projects/sql_injection/
MODEL_PATH = ROOT / "models" / "best_model.pkl"
PREPROC_PATH = ROOT / "models" / "preprocessor.pkl"


class SQLiDetector:
    _instance = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance

    def _load(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(PREPROC_PATH)
            logger.info("SQLi ML model loaded")
        except Exception as e:
            logger.error(f"Failed to load SQLi model: {e}")
            self.model = self.scaler = None

    def predict(self, request: dict, response: dict) -> dict:
        """
        request : dict with keys: url, method, payload (or body), headers, etc.
        response: raw requests.Response object (has .text, .status_code, .elapsed)
        Returns: {'ml_label': 0/1, 'ml_confidence': float}
        """
        if self.model is None:
            return {"ml_label": "unknown", "ml_confidence": 0.0}

        # Build a one-row DataFrame that mimics the training dataset
        payload = request.get("payload", "")
        row = {
            "payload": payload,
            "url_len": len(request.get("url", "")),
            "payload_len": len(payload),
            "has_sql_keywords": int(any(k in payload.lower() for k in
                                      ["select", "union", "insert", "delete", "drop", "alter", "--", ";"])),
            "response_time": response.elapsed.total_seconds(),
            "status_code": response.status_code,
            "html_len": len(response.text),
            "error_flag": int("error" in response.text.lower() or "syntax" in response.text.lower()),
            "reflected_flag": int(payload in response.text),
        }
        df = pd.DataFrame([row])
        X = extract_features(df)                 # same function used in training
        X_s = self.scaler.transform(X)

        label = int(self.model.predict(X_s)[0])
        prob = self.model.predict_proba(X_s)[0]
        confidence = float(prob.max())
        return {"ml_label": label, "ml_confidence": round(confidence, 4)}