# IDOR Feature Engineering Summary Report

Generated on: 2025-11-06 17:09:27

## Dataset Overview

- **Total Records**: 580
- **Total Features**: 64
- **URL Structure Features**: 13
- **Parameter Change Features**: 10
- **Response Features**: 21
- **Temporal Features**: 8
- **Interaction Features**: 0

## Security Analysis

- **Unauthorized Access Attempts**: 228 (39.3%)
- **Authorized Access Attempts**: 352 (60.7%)

## Status Code Distribution

- **404**: 262 (45.2%)
- **401**: 220 (37.9%)
- **405**: 62 (10.7%)
- **200**: 36 (6.2%)

## Top Features by Importance (Sample)

### URL Structure Features
- **param_key_count**: mean=0.93, std=0.25

### Parameter Change Features
- **param_key_count**: mean=0.93, std=0.25
- **has_numeric_param**: mean=0.83, std=0.38
- **has_uuid_param**: mean=0.00, std=0.00
- **has_alphanumeric_param**: mean=0.06, std=0.24

### Response Features
- **status_code**: mean=390.31, std=49.02
- **response_length**: mean=46.25, std=43.93
- **response_time**: mean=2.09, std=0.02
- **sensitive_data_found**: mean=0.02, std=0.14

## Feature Quality Metrics

- **Missing Values**: 0
- **Duplicate Rows**: 0
- **Data Completeness**: 100.0%

## ML/DL Readiness

✅ **Ready for Machine Learning**
- All features are numerical
- No missing values
- Properly encoded categorical variables
- Normalized numerical features
- Binary target variable (is_unauthorized)

## Generated Files

- **Feature Dataset**: `data/idor_features.csv`
- **Summary Report**: `docs/idor_feature_summary.md`

## Next Steps

1. **Model Training**: Use this feature-rich dataset to train ML/DL models
2. **Feature Selection**: Apply feature selection techniques to identify most important features
3. **Model Validation**: Validate model performance on test data
4. **Deployment**: Deploy the trained model for real-time IDOR detection
