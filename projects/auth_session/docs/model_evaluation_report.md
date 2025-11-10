
# Model Evaluation Report

## Dataset Used
- **Source:** `projects/auth_session/data/feature_dataset.csv`
- **Shape:** (565, 35)

## Feature Set Overview
- **Features:** ['timestamp', 'event_id', 'username', 'user_id', 'ip_address', 'user_agent', 'endpoint', 'method', 'status_code', 'auth_result', 'failure_reason', 'attempt_count_for_username', 'attempt_count_from_ip', 'time_since_last_attempt_for_username', 'session_id', 'is_bruteforce_candidate', 'notes', 'ip_address_code', 'user_agent_code', 'username_code', 'is_failure', 'is_success', 'fail_count_5m', 'fail_count_15m', 'fail_count_60m', 'succ_count_60m', 'fail_success_ratio', 'distinct_ips_60m', 'distinct_user_agents_60m', 'attempts_per_minute', 'distinct_usernames_attempted', 'login_hour_local', 'weekday', 'entropy_of_username']

## Model Parameters
### Isolation Forest
- `n_estimators`: 100
- `contamination`: 'auto'
- `max_samples`: 'auto'

### Autoencoder
- **Architecture:** Input -> Dense(16, relu) -> Dense(22, sigmoid)
- **Optimizer:** Adam
- **Loss Function:** Mean Squared Error (MSE)
- **Epochs:** 50

## Key Results

### Isolation Forest
- **Accuracy:** 0.6706
- **Precision:** 0.0000
- **Recall:** 0.0000
- **F1-score:** 0.0000
- **False Positive Rate:** 0.3294
- **False Negative Rate:** nan
- **Confusion Matrix:**
  ```
  [[57 28]
 [ 0  0]]
  ```

### Autoencoder
- **Accuracy:** 0.9765
- **Precision:** 0.0000
- **Recall:** 0.0000
- **F1-score:** 0.0000
- **False Positive Rate:** 0.0235
- **False Negative Rate:** nan
- **Confusion Matrix:**
  ```
  [[83  2]
 [ 0  0]]
  ```

## Recommendations
- **Threshold Tuning:** The Autoencoder's performance is sensitive to the anomaly threshold. Further tuning could improve the trade-off between precision and recall.
- **Feature Pruning:** Analyze feature importance to see if a smaller feature set could yield similar or better results, reducing model complexity.
