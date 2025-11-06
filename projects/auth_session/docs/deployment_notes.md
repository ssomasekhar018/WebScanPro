# Deployment Notes: Auth Anomaly Detection API

## Overview
This document describes how to deploy the anomaly detection models (Isolation Forest and One-Class SVM) as a REST API for real-time authentication/session anomaly detection.

## Artifacts
- Models: `projects/auth_session/ml/isolation_forest_model.pkl`, `projects/auth_session/ml/oneclass_svm_model.pkl`
- Scaler: `projects/auth_session/ml/scaler.pkl`
- Inference code: `projects/auth_session/ml/inference.py`
- API service: `projects/auth_session/deployment/api.py`
- Dockerfile: `projects/auth_session/deployment/Dockerfile`
- Requirements: `projects/auth_session/deployment/requirements.txt`

## Local Run (no Docker)
```bash
# From project root
python projects/auth_session/deployment/api.py
# API at http://localhost:8000
# Health check
curl http://localhost:8000/health
# Prediction
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"data": [{"fail_count_5m": 12, "distinct_ips_60m": 6, "attempts_per_minute": 30}]}'
```

## Docker Build & Run
```bash
# From project root
cd projects/auth_session/deployment
docker build -t auth-anomaly-api .
docker run --rm -p 8000:8000 auth-anomaly-api
```

## Input Schema
POST /predict accepts a JSON body with a `data` array of objects. Each object should include the numeric feature fields used in training. Missing fields default to 0, extra fields are ignored.

Example:
```json
{
  "data": [
    {
      "fail_count_5m": 12,
      "fail_count_60m": 40,
      "distinct_ips_60m": 6,
      "attempts_per_minute": 25,
      "velocity_score": 0.8
    }
  ]
}
```

## Output Schema
```json
{
  "isolation_forest": {"pred": [0, 1], "score": [0.12, 0.85]},
  "oneclass_svm": {"pred": [0, 1], "score": [0.05, 1.10]},
  "ensemble": {"pred": [0, 1]}
}
```

- `pred`: 0 = normal, 1 = anomalous
- `score`: higher typically means more anomalous (model-dependent)
- `ensemble`: max over available models

## Security & PII
- Inputs should already be anonymized (HMAC of username/IP/session)
- Add API auth (e.g., API key header) and rate limiting before production

## Performance Targets
- Latency < 500ms per /predict call
- Batch multiple events in one request for efficiency

## Monitoring
- Inference logs: `projects/auth_session/logs/inference_<timestamp>.log`
- Expose metrics endpoint (e.g., Prometheus) if needed

## Integration Tips
- Build a small adapter that reads new auth logs (ELK/file), transforms to features (match feature columns), and posts to /predict
- Use response to trigger alerts or actions (account lock, captcha, notification)

## Retraining
- Periodically rerun training with recent data
- Version and store models alongside metadata (feature list, thresholds, dataset timestamp)


