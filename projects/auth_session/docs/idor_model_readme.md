# IDOR Model Readme

This document provides a brief overview of the IDOR detection model.

## Model Details

*   **Model Type:** Logistic Regression
*   **Features:** `param_key_count`, `self_access`, `param_change_rate`, `status_code_cat`, `response_length`, `sensitive_data_found`

## Limitations

The model was trained on a very small dataset and has poor performance. It is not recommended for use in a production environment. The model should be retrained on a larger, more representative dataset before being used for any real-world applications.
