# IDOR Model Evaluation Report (v2)
Generated: 2026-07-03 16:12:20

## Dataset
- **Source**: `projects/auth_session/data/idor_dataset_synthetic.csv`
- **Shape**: (1200, 12)
- **IDOR Ratio**: 28.0%

## Feature Set (17 features)
- `param_key_count`
- `param_is_numeric`
- `param_is_sequential`
- `param_delta`
- `path_depth`
- `self_access`
- `param_change_rate`
- `status_code_cat`
- `status_is_200`
- `status_is_403`
- `status_is_404`
- `response_length`
- `response_is_large`
- `sensitive_data_found`
- `is_get`
- `is_post`
- `has_auth_header`

## Results

| Metric     | Isolation Forest | Autoencoder | Random Forest |
|------------|-----------------|-------------|---------------|
| Accuracy   | 0.5833 | 0.6667 | 1.0000 |
| Precision  | 0.3239 | 0.0000 | 1.0000 |
| Recall     | 0.4600 | 0.0000 | 1.0000 |
| F1-score   | 0.3802 | 0.0000 | 1.0000 |
| AUC-ROC    | 0.6457 | 0.5671 | 1.0000 |
| FPR        | 0.3692 | 0.0769 | 0.0000 |
| FNR        | 0.5400 | 1.0000 | 0.0000 |

## Top Feature Importances (Random Forest)
- `self_access`: 0.3299
- `param_delta`: 0.3071
- `sensitive_data_found`: 0.0638
- `status_code_cat`: 0.0597
- `response_length`: 0.0589
- `has_auth_header`: 0.0563
- `status_is_200`: 0.0463
- `response_is_large`: 0.0234
- `is_post`: 0.0153
- `status_is_404`: 0.0113

## Recommendations
- **Random Forest** is the recommended production model (supervised, interpretable).
- Isolation Forest is useful for zero-shot anomaly detection on new endpoints.
- Autoencoder threshold can be tuned to reduce FPR.
