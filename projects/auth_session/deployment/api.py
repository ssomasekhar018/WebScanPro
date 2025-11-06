#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import pandas as pd
import uvicorn
import os
import sys

# Ensure imports work when run from project root or this directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "projects", "auth_session"))

from ml.inference import InferenceEngine  # noqa: E402


app = FastAPI(title="Auth Anomaly Detection API", version="1.0")
engine = InferenceEngine()


class EventBatch(BaseModel):
    data: List[Dict[str, Any]]


@app.get("/health")
def health():
    return {"status": "ok", "models": {
        "if": engine.iso_forest is not None,
        "ocsvm": engine.oneclass_svm is not None,
        "ae": engine.autoencoder is not None,
    }}


@app.post("/predict")
def predict(batch: EventBatch):
    try:
        if not batch.data:
            raise ValueError("Empty payload")
        df = pd.DataFrame(batch.data)
        results = engine.predict(df)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))


