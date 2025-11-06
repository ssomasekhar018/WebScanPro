# Feature Extraction Summary for Web Security

## Extracted Features and Examples (from your dataset):
- **input_length**: Total characters in default_value (e.g., 0 for username, 32 for user_token).
- **num_special_chars**: Count of < > ' " % & (e.g., 0 across all, as no symbols present).
- **num_digits**: Count of 0-9 (e.g., 0 for "Login", 16 for hex user_token).
- **param_type**: Input type (e.g., "text", "hidden").
- **contains_sql_keyword**: 1/0 for SQL terms (all 0 in your data).
- **contains_html_tag**: 1/0 for HTML tags (all 0 in your data).

## Why Useful for Security Detection:
These features quantify input patterns for ML models to detect anomalies. E.g., high num_special_chars + contains_html_tag=1 could flag XSS. In your login form data, all benign (lengths short, no code-like patterns), but with real attack data (e.g., SQL injection in input_value), models can classify risks. This aids in building detectors for vulnerabilities like injection attacks.