# IDOR Detection Dataset Summary

## Dataset Overview
- **Total Records**: 2,000
- **Created**: 2025-11-05T23:08:46.171633
- **Data Source**: Synthetic IDOR Detection Dataset

## Access Control Analysis
- **Authorized Access**: 505 (25.2%)
- **Unauthorized Access**: 1,495 (74.8%)

## Vulnerability Detection
- **Vulnerable Requests**: 56
- **Secure Requests**: 1,439
- **Vulnerability Rate**: 3.7%

## Response Analysis
- **Average Response Length**: 1027 bytes
- **Average Response Time**: 0.254 seconds
- **Sensitive Data Exposed**: 479 cases

## Status Code Distribution
- **403**: 1,012 (50.6%)
- **200**: 536 (26.8%)
- **401**: 349 (17.4%)
- **404**: 78 (3.9%)
- **204**: 14 (0.7%)
- **201**: 11 (0.5%)

## Method Distribution
- **POST**: 528 (26.4%)
- **PUT**: 501 (25.1%)
- **DELETE**: 487 (24.3%)
- **GET**: 484 (24.2%)

## Top Endpoint Patterns
- **/report?report_id={}**: 165 (8.2%)
- **/document?doc_id={}**: 149 (7.4%)
- **/messages/{}/view**: 145 (7.2%)
- **/user/profile?user_id={}**: 139 (7.0%)
- **/invoice?id={}**: 134 (6.7%)

## Quality Metrics
- **Completeness**: 100.0%
- **Duplicate Records**: 0
- **Test Coverage**: 15 unique endpoints

## Key Findings
1. **IDOR Vulnerabilities**: 56 requests successfully accessed unauthorized resources
2. **Security Controls**: 1,439 requests were properly blocked
3. **Data Quality**: Dataset is 100.0% complete with 0 duplicates removed
4. **Coverage**: Tests cover 15 different endpoint patterns

## Dataset Features
- **Request ID**: Unique identifier for each request
- **Endpoint**: Full endpoint URL with parameters
- **Method**: HTTP method (GET, POST, PUT, DELETE)
- **Parameter**: Extracted parameter name
- **User ID**: ID of the requesting user
- **Target ID**: ID of the requested resource
- **Status Code**: HTTP response status code
- **Response Length**: Size of response in bytes
- **Response Time**: Server response time in seconds
- **Sensitive Data Found**: Binary indicator for sensitive data exposure
- **Is Unauthorized**: Binary label (0=authorized, 1=unauthorized)
- **Timestamp**: Request timestamp

## ML/DL Readiness
This dataset is optimized for machine learning with:
- Encoded categorical variables (method_encoded, endpoint_encoded, parameter_encoded)
- Numerical features (user_id_int, target_id_int, id_difference)
- Binary classification target (is_unauthorized)
- Balanced representation of vulnerable and secure scenarios
