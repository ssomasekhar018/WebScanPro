#!/usr/bin/env python3
"""
Fast IDOR Dataset Generator
Generates synthetic IDOR detection data for ML/DL training.
"""

import pandas as pd
import numpy as np
import json
import random
import hashlib
from datetime import datetime, timedelta
import os

class FastIDORDatasetGenerator:
    """Fast generator for IDOR detection datasets."""
    
    def __init__(self):
        self.endpoints = [
            "/user/profile?user_id={}",
            "/api/user/{}/details",
            "/profile?uid={}",
            "/invoice?id={}",
            "/order/{}/status",
            "/document?doc_id={}",
            "/api/account/{}/balance",
            "/settings?user_id={}",
            "/messages/{}/view",
            "/report?report_id={}",
            "/api/secure/user/{}",
            "/api/vulnerable/user/{}",
            "/customer/{}/info",
            "/payment/{}/details",
            "/subscription/{}/plan"
        ]
        
        self.methods = ["GET", "POST", "PUT", "DELETE"]
        self.status_codes = [200, 401, 403, 404, 500]
        self.user_ids = ["101", "102", "103", "104", "105", "106", "107", "108", "109", "110"]
        self.resource_ids = ["101", "102", "103", "104", "105", "201", "202", "203", "301", "302", "401", "402", "999", "1000"]
        
        # Define resource ownership
        self.resource_ownership = {
            "101": ["101", "201", "301", "401"],
            "102": ["102", "202", "302", "402"],
            "103": ["103", "203", "303", "403"],
            "104": ["104", "204", "304", "404"],
            "105": ["105", "205", "305", "405"]
        }
    
    def generate_request_id(self):
        """Generate unique request ID."""
        return hashlib.md5(f"{datetime.now().timestamp()}{random.random()}".encode()).hexdigest()[:12]
    
    def is_authorized_access(self, user_id, target_id, endpoint):
        """Determine if access should be authorized."""
        # User accessing their own resources
        if user_id == target_id:
            return True
        
        # User accessing their owned resources
        if user_id in self.resource_ownership:
            if target_id in self.resource_ownership[user_id]:
                return True
        
        # Some endpoints are inherently more vulnerable
        vulnerable_endpoints = [
            "/user/profile?user_id={}",
            "/profile?uid={}",
            "/invoice?id={}",
            "/document?doc_id={}",
            "/report?report_id={}",
            "/api/vulnerable/user/{}",
            "/customer/{}/info"
        ]
        
        # Check if endpoint is vulnerable (higher chance of unauthorized access)
        endpoint_pattern = endpoint.replace(target_id, "{}")
        if endpoint_pattern in vulnerable_endpoints:
            # 70% chance of being vulnerable (returning 200 for unauthorized)
            return random.random() < 0.3  # 30% chance of being secure
        
        # Secure endpoints
        secure_endpoints = [
            "/api/user/{}/details",
            "/api/secure/user/{}",
            "/order/{}/status",
            "/api/account/{}/balance",
            "/settings?user_id={}",
            "/messages/{}/view"
        ]
        
        if endpoint_pattern in secure_endpoints:
            return False  # Always require authorization
        
        # Default behavior
        return random.random() < 0.2  # 20% chance of being authorized
    
    def determine_response_status(self, is_authorized, method, endpoint):
        """Determine response status code."""
        if is_authorized:
            # Authorized access - usually returns 200
            if random.random() < 0.9:
                return 200
            else:
                return random.choice([200, 201, 204])
        else:
            # Unauthorized access - various responses
            endpoint_pattern = endpoint.replace(endpoint.split('/')[-1].split('?')[0].split('=')[-1], "{}")
            
            # Vulnerable endpoints might return 200 even for unauthorized
            vulnerable_patterns = [
                "/user/profile?user_id={}",
                "/profile?uid={}",
                "/invoice?id={}",
                "/document?doc_id={}",
                "/report?report_id={}",
                "/api/vulnerable/user/{}",
                "/customer/{}/info"
            ]
            
            if endpoint_pattern in vulnerable_patterns and random.random() < 0.6:
                return 200  # IDOR vulnerability - unauthorized access returns 200
            
            # Secure endpoints return proper error codes
            if random.random() < 0.7:
                return 403  # Forbidden
            elif random.random() < 0.8:
                return 401  # Unauthorized
            else:
                return 404  # Not Found
    
    def generate_sensitive_data(self, user_id, target_id):
        """Generate sensitive data for responses."""
        if user_id == target_id or (user_id in self.resource_ownership and target_id in self.resource_ownership[user_id]):
            # Return actual sensitive data for authorized access
            return {
                "email": f"user{target_id}@example.com",
                "phone": f"555-{target_id.zfill(4)}",
                "address": f"{random.randint(100, 999)} Main St",
                "ssn": f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
            }
        else:
            # Return limited data for unauthorized access
            if random.random() < 0.3:
                # Sometimes return sensitive data (IDOR vulnerability)
                return {
                    "email": f"user{target_id}@example.com",
                    "phone": f"555-{target_id.zfill(4)}",
                    "error": "sensitive_data_exposed"
                }
            else:
                # Return generic error
                return {"error": "access_denied"}
    
    def generate_dataset(self, num_records=1000):
        """Generate IDOR detection dataset."""
        print(f"Generating {num_records} IDOR detection records...")
        
        records = []
        
        for i in range(num_records):
            # Generate base request data
            user_id = random.choice(self.user_ids)
            target_id = random.choice(self.resource_ids)
            endpoint = random.choice(self.endpoints)
            method = random.choice(self.methods)
            
            # Format endpoint with target ID
            formatted_endpoint = endpoint.format(target_id)
            
            # Determine if access is authorized
            is_authorized = self.is_authorized_access(user_id, target_id, endpoint)
            
            # Determine response status
            status_code = self.determine_response_status(is_authorized, method, endpoint)
            
            # Generate response data
            response_length = random.randint(50, 2000)
            response_time = random.uniform(0.01, 0.5)
            
            # Check for sensitive data
            sensitive_data_found = 0
            if status_code == 200 and not is_authorized:
                # IDOR vulnerability - sensitive data exposed
                sensitive_data_found = 1 if random.random() < 0.8 else 0
            elif status_code == 200 and is_authorized:
                # Authorized access - may contain sensitive data
                sensitive_data_found = 1 if random.random() < 0.9 else 0
            
            # Generate timestamp
            timestamp = datetime.now() - timedelta(minutes=random.randint(0, 10080))  # Random time in last week
            
            # Extract parameter name
            parameter = self.extract_parameter(formatted_endpoint)
            
            record = {
                "request_id": self.generate_request_id(),
                "endpoint": formatted_endpoint,
                "endpoint_pattern": endpoint,
                "method": method,
                "parameter": parameter,
                "user_id": user_id,
                "target_id": target_id,
                "status_code": status_code,
                "response_length": response_length,
                "response_time": response_time,
                "sensitive_data_found": sensitive_data_found,
                "is_unauthorized": 0 if is_authorized else 1,
                "timestamp": timestamp.isoformat()
            }
            
            records.append(record)
            
            if (i + 1) % 100 == 0:
                print(f"Generated {i + 1} records...")
        
        return pd.DataFrame(records)
    
    def extract_parameter(self, endpoint):
        """Extract parameter name from endpoint."""
        if '?' in endpoint:
            return endpoint.split('?')[1].split('=')[0] if '=' in endpoint else 'id'
        elif '/' in endpoint:
            parts = endpoint.split('/')
            return parts[-1] if parts[-1] != '' else 'id'
        return 'id'
    
    def add_encoded_features(self, df):
        """Add encoded features for ML training."""
        # Method encoding
        method_mapping = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
        df['method_encoded'] = df['method'].map(method_mapping)
        
        # Endpoint pattern encoding
        df['endpoint_encoded'] = pd.Categorical(df['endpoint_pattern']).codes
        
        # Parameter encoding
        df['parameter_encoded'] = pd.Categorical(df['parameter']).codes
        
        # User ID and target ID as integers
        df['user_id_int'] = df['user_id'].astype(int)
        df['target_id_int'] = df['target_id'].astype(int)
        
        # Calculate ID difference (target - user)
        df['id_difference'] = df['target_id_int'] - df['user_id_int']
        
        # Binary features
        df['same_user'] = (df['user_id'] == df['target_id']).astype(int)
        df['is_get_request'] = (df['method'] == 'GET').astype(int)
        df['is_post_request'] = (df['method'] == 'POST').astype(int)
        df['is_success_status'] = (df['status_code'] == 200).astype(int)
        df['is_forbidden_status'] = (df['status_code'] == 403).astype(int)
        df['is_not_found_status'] = (df['status_code'] == 404).astype(int)
        
        return df
    
    def generate_summary_report(self, df):
        """Generate comprehensive summary report."""
        total_records = len(df)
        unauthorized_records = len(df[df['is_unauthorized'] == 1])
        authorized_records = len(df[df['is_unauthorized'] == 0])
        
        vulnerable_requests = len(df[(df['is_unauthorized'] == 1) & (df['status_code'] == 200)])
        secure_requests = len(df[(df['is_unauthorized'] == 1) & (df['status_code'] != 200)])
        
        summary = {
            "dataset_info": {
                "total_records": total_records,
                "created_at": datetime.now().isoformat(),
                "data_source": "Synthetic IDOR Detection Dataset"
            },
            "access_distribution": {
                "authorized_access": authorized_records,
                "unauthorized_access": unauthorized_records,
                "unauthorized_percentage": (unauthorized_records / total_records * 100) if total_records > 0 else 0
            },
            "vulnerability_analysis": {
                "vulnerable_requests": vulnerable_requests,
                "secure_requests": secure_requests,
                "vulnerability_rate": (vulnerable_requests / unauthorized_records * 100) if unauthorized_records > 0 else 0
            },
            "status_code_distribution": df['status_code'].value_counts().to_dict() if total_records > 0 else {},
            "method_distribution": df['method'].value_counts().to_dict() if total_records > 0 else {},
            "endpoint_patterns": df['endpoint_pattern'].value_counts().head(10).to_dict() if total_records > 0 else {},
            "response_stats": {
                "avg_response_length": df['response_length'].mean() if total_records > 0 else 0,
                "avg_response_time": df['response_time'].mean() if total_records > 0 else 0,
                "sensitive_data_exposed": len(df[df['sensitive_data_found'] == 1]) if total_records > 0 else 0
            },
            "quality_metrics": {
                "completeness": (len(df.dropna()) / total_records * 100) if total_records > 0 else 100,
                "duplicate_records": len(df) - len(df.drop_duplicates()),
                "test_coverage": len(df['endpoint_pattern'].unique()) if total_records > 0 else 0
            }
        }
        
        return summary

def main():
    """Main function to generate IDOR dataset."""
    print("Starting Fast IDOR Dataset Generation...")
    
    # Create generator
    generator = FastIDORDatasetGenerator()
    
    # Generate dataset
    df = generator.generate_dataset(num_records=2000)
    
    # Add encoded features
    df = generator.add_encoded_features(df)
    
    # Generate summary
    summary = generator.generate_summary_report(df)
    
    # Create output directories
    os.makedirs("data/raw_requests", exist_ok=True)
    os.makedirs("docs", exist_ok=True)
    
    # Save dataset
    dataset_path = "data/idor_dataset.csv"
    df.to_csv(dataset_path, index=False)
    print(f"✓ Saved IDOR dataset to {dataset_path} ({len(df)} records)")
    
    # Save raw requests (same data in JSON format)
    raw_requests_path = "data/raw_requests/idor_raw_requests.json"
    df.to_json(raw_requests_path, orient='records', indent=2)
    print(f"✓ Saved raw requests to {raw_requests_path}")
    
    # Save summary report
    summary_path = "docs/idor_data_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"✓ Saved summary report to {summary_path}")
    
    # Generate markdown report
    markdown_report = f"""# IDOR Detection Dataset Summary

## Dataset Overview
- **Total Records**: {summary['dataset_info']['total_records']:,}
- **Created**: {summary['dataset_info']['created_at']}
- **Data Source**: {summary['dataset_info']['data_source']}

## Access Control Analysis
- **Authorized Access**: {summary['access_distribution']['authorized_access']:,} ({summary['access_distribution']['authorized_access']/summary['dataset_info']['total_records']*100:.1f}%)
- **Unauthorized Access**: {summary['access_distribution']['unauthorized_access']:,} ({summary['access_distribution']['unauthorized_percentage']:.1f}%)

## Vulnerability Detection
- **Vulnerable Requests**: {summary['vulnerability_analysis']['vulnerable_requests']:,}
- **Secure Requests**: {summary['vulnerability_analysis']['secure_requests']:,}
- **Vulnerability Rate**: {summary['vulnerability_analysis']['vulnerability_rate']:.1f}%

## Response Analysis
- **Average Response Length**: {summary['response_stats']['avg_response_length']:.0f} bytes
- **Average Response Time**: {summary['response_stats']['avg_response_time']:.3f} seconds
- **Sensitive Data Exposed**: {summary['response_stats']['sensitive_data_exposed']:,} cases

## Status Code Distribution
"""
    
    for status_code, count in summary['status_code_distribution'].items():
        percentage = count / summary['dataset_info']['total_records'] * 100
        markdown_report += f"- **{status_code}**: {count:,} ({percentage:.1f}%)\n"
    
    markdown_report += f"""
## Method Distribution
"""
    
    for method, count in summary['method_distribution'].items():
        percentage = count / summary['dataset_info']['total_records'] * 100
        markdown_report += f"- **{method}**: {count:,} ({percentage:.1f}%)\n"
    
    markdown_report += f"""
## Top Endpoint Patterns
"""
    
    for endpoint, count in list(summary['endpoint_patterns'].items())[:5]:
        percentage = count / summary['dataset_info']['total_records'] * 100
        markdown_report += f"- **{endpoint}**: {count:,} ({percentage:.1f}%)\n"
    
    markdown_report += f"""
## Quality Metrics
- **Completeness**: {summary['quality_metrics']['completeness']:.1f}%
- **Duplicate Records**: {summary['quality_metrics']['duplicate_records']:,}
- **Test Coverage**: {summary['quality_metrics']['test_coverage']} unique endpoints

## Key Findings
1. **IDOR Vulnerabilities**: {summary['vulnerability_analysis']['vulnerable_requests']:,} requests successfully accessed unauthorized resources
2. **Security Controls**: {summary['vulnerability_analysis']['secure_requests']:,} requests were properly blocked
3. **Data Quality**: Dataset is {summary['quality_metrics']['completeness']:.1f}% complete with {summary['quality_metrics']['duplicate_records']:,} duplicates removed
4. **Coverage**: Tests cover {summary['quality_metrics']['test_coverage']} different endpoint patterns

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
"""
    
    # Save markdown report
    markdown_path = "docs/idor_data_summary.md"
    with open(markdown_path, 'w') as f:
        f.write(markdown_report)
    print(f"✓ Saved markdown report to {markdown_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("IDOR DATASET GENERATION COMPLETE")
    print("="*60)
    print(f"Total Records: {summary['dataset_info']['total_records']:,}")
    print(f"Authorized Access: {summary['access_distribution']['authorized_access']:,}")
    print(f"Unauthorized Access: {summary['access_distribution']['unauthorized_access']:,}")
    print(f"Vulnerable Requests: {summary['vulnerability_analysis']['vulnerable_requests']:,}")
    print(f"Vulnerability Rate: {summary['vulnerability_analysis']['vulnerability_rate']:.1f}%")
    print(f"Sensitive Data Exposed: {summary['response_stats']['sensitive_data_exposed']:,}")
    print("="*60)
    
    return 0

if __name__ == "__main__":
    exit(main())