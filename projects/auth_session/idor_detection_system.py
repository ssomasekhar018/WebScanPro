#!/usr/bin/env python3
"""
IDOR Detection System with ML/DL Integration
Collects and curates parameterized web requests to identify potential IDOR vulnerabilities.
"""

import json
import csv
import time
import random
import hashlib
import requests
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IDORDetectionSystem:
    """
    Comprehensive IDOR vulnerability detection system.
    Collects parameterized requests and tests for unauthorized access scenarios.
    """
    
    def __init__(self, base_url: str = "http://localhost:5000", output_dir: str = "data"):
        """
        Initialize IDOR detection system.
        
        Args:
            base_url: Base URL for testing
            output_dir: Directory for output files
        """
        self.base_url = base_url.rstrip('/')
        self.output_dir = output_dir
        self.raw_requests_dir = f"{output_dir}/raw_requests"
        self.session = requests.Session()
        self.test_users = {}
        self.collected_requests = []
        self.test_results = []
        
        # Sample endpoints for testing
        self.test_endpoints = [
            "/user/profile?user_id={}",
            "/api/user/{}/details",
            "/profile?uid={}",
            "/invoice?id={}",
            "/order/{}/status",
            "/document?doc_id={}",
            "/api/account/{}/balance",
            "/settings?user_id={}",
            "/messages/{}/view",
            "/report?report_id={}"
        ]
        
        logger.info(f"IDOR Detection System initialized for {base_url}")
    
    def setup_test_users(self) -> None:
        """Setup test users with authentication tokens."""
        logger.info("Setting up test users...")
        
        # Mock test users with different resource ownership
        self.test_users = {
            "user_a": {
                "user_id": "101",
                "username": "test_user_a",
                "token": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTAxIn0.mock_token_a",
                "owned_resources": ["101", "201", "301"]  # IDs this user should access
            },
            "user_b": {
                "user_id": "102", 
                "username": "test_user_b",
                "token": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTAyIn0.mock_token_b",
                "owned_resources": ["102", "202", "302"]  # IDs this user should access
            }
        }
        
        logger.info(f"Created {len(self.test_users)} test users")
    
    def generate_test_resource_ids(self) -> List[str]:
        """Generate a comprehensive list of test resource IDs."""
        # Mix of valid and potentially invalid IDs
        return [
            "101", "102", "103", "104", "105",  # User IDs
            "201", "202", "203", "204", "205",  # Profile IDs  
            "301", "302", "303", "304", "305",  # Document IDs
            "401", "402", "403", "404", "405",  # Invoice IDs
            "999", "1000", "1001", "-1", "0",   # Edge cases
            "abc", "xyz", "../../../etc/passwd", "' OR '1'='1"  # Malicious attempts
        ]
    
    def collect_authorized_requests(self) -> None:
        """Collect legitimate requests for users accessing their own data."""
        logger.info("Collecting authorized requests...")
        
        resource_ids = self.generate_test_resource_ids()
        
        for user_key, user_data in self.test_users.items():
            headers = {"Authorization": user_data["token"]}
            
            for endpoint_template in self.test_endpoints:
                for resource_id in user_data["owned_resources"]:
                    if resource_id in resource_ids:
                        try:
                            # Format endpoint with resource ID
                            endpoint = endpoint_template.format(resource_id)
                            url = urljoin(self.base_url, endpoint)
                            
                            # Determine HTTP method
                            method = "GET"
                            if "api/" in endpoint and "delete" not in endpoint.lower():
                                method = random.choice(["GET", "POST"])
                            
                            # Make request
                            response = self.session.request(method, url, headers=headers, timeout=5)
                            
                            # Record request details
                            request_data = {
                                "request_id": self._generate_request_id(),
                                "timestamp": datetime.now().isoformat(),
                                "user_key": user_key,
                                "user_id": user_data["user_id"],
                                "target_id": resource_id,
                                "endpoint": endpoint,
                                "method": method,
                                "url": url,
                                "headers": dict(headers),
                                "status_code": response.status_code,
                                "response_length": len(response.content),
                                "response_headers": dict(response.headers),
                                "sensitive_data_found": self._detect_sensitive_data(response),
                                "is_unauthorized": 0,  # Legitimate access
                                "access_type": "authorized",
                                "response_time": response.elapsed.total_seconds()
                            }
                            
                            self.collected_requests.append(request_data)
                            logger.info(f"Collected authorized request: {method} {endpoint} -> {response.status_code}")
                            
                            # Small delay to avoid overwhelming the server
                            time.sleep(0.1)
                            
                        except Exception as e:
                            logger.warning(f"Failed to collect authorized request for {endpoint}: {e}")
    
    def test_unauthorized_access_scenarios(self) -> None:
        """Test unauthorized access by modifying identifiers."""
        logger.info("Testing unauthorized access scenarios...")
        
        resource_ids = self.generate_test_resource_ids()
        
        for user_key, user_data in self.test_users.items():
            headers = {"Authorization": user_data["token"]}
            
            for endpoint_template in self.test_endpoints:
                for resource_id in resource_ids:
                    # Skip if this resource belongs to the current user
                    if resource_id in user_data["owned_resources"]:
                        continue
                    
                    try:
                        # Format endpoint with unauthorized resource ID
                        endpoint = endpoint_template.format(resource_id)
                        url = urljoin(self.base_url, endpoint)
                        
                        # Determine HTTP method
                        method = "GET"
                        if "api/" in endpoint and "delete" not in endpoint.lower():
                            method = random.choice(["GET", "POST"])
                        
                        # Make unauthorized request
                        response = self.session.request(method, url, headers=headers, timeout=5)
                        
                        # Determine if this is actually unauthorized access
                        is_unauthorized = self._determine_unauthorized_access(response, resource_id, user_data)
                        
                        # Record test result
                        test_data = {
                            "request_id": self._generate_request_id(),
                            "timestamp": datetime.now().isoformat(),
                            "user_key": user_key,
                            "user_id": user_data["user_id"],
                            "target_id": resource_id,
                            "endpoint": endpoint,
                            "method": method,
                            "url": url,
                            "headers": dict(headers),
                            "status_code": response.status_code,
                            "response_length": len(response.content),
                            "response_headers": dict(response.headers),
                            "sensitive_data_found": self._detect_sensitive_data(response),
                            "is_unauthorized": is_unauthorized,
                            "access_type": "unauthorized_test",
                            "response_time": response.elapsed.total_seconds()
                        }
                        
                        self.test_results.append(test_data)
                        
                        if is_unauthorized == 1:
                            logger.warning(f"POTENTIAL IDOR: {method} {endpoint} -> {response.status_code} (UNAUTHORIZED ACCESS DETECTED)")
                        else:
                            logger.info(f"Secure access control: {method} {endpoint} -> {response.status_code}")
                        
                        # Small delay
                        time.sleep(0.1)
                        
                    except Exception as e:
                        logger.warning(f"Failed to test unauthorized access for {endpoint}: {e}")
    
    def _determine_unauthorized_access(self, response: requests.Response, target_id: str, user_data: dict) -> int:
        """
        Determine if unauthorized access was successful.
        
        Args:
            response: HTTP response
            target_id: Target resource ID
            user_data: Current user data
            
        Returns:
            1 if unauthorized access detected, 0 otherwise
        """
        # Check for successful access to unauthorized resource
        if response.status_code == 200:
            # Additional checks for potential data leakage
            response_text = response.text.lower()
            
            # Look for sensitive data patterns
            sensitive_patterns = [
                "email", "phone", "address", "ssn", "password",
                "credit", "card", "bank", "account", "personal"
            ]
            
            has_sensitive_data = any(pattern in response_text for pattern in sensitive_patterns)
            
            # If we get 200 with sensitive data for a resource not owned by user, it's unauthorized
            if has_sensitive_data and target_id not in user_data["owned_resources"]:
                return 1
        
        # Check for other suspicious patterns
        elif response.status_code in [403, 401]:
            # Proper access control - mark as secure
            return 0
        elif response.status_code == 404:
            # Resource not found - could be secure or insecure depending on implementation
            return 0
        
        return 0
    
    def _detect_sensitive_data(self, response: requests.Response) -> int:
        """
        Detect if response contains sensitive data.
        
        Args:
            response: HTTP response
            
        Returns:
            1 if sensitive data found, 0 otherwise
        """
        response_text = response.text.lower()
        
        # Patterns indicating sensitive data
        sensitive_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{3}-\d{3}-\d{4}\b',  # Phone
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
            r'password', 'email', 'phone', 'address', 'ssn'
        ]
        
        import re
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text):
                return 1
        
        return 0
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        timestamp = str(time.time())
        return hashlib.md5(timestamp.encode()).hexdigest()[:12]
    
    def save_raw_requests(self) -> None:
        """Save collected requests to raw requests directory."""
        logger.info("Saving raw requests...")
        
        # Combine all requests
        all_requests = self.collected_requests + self.test_results
        
        # Save as JSON
        json_file = f"{self.raw_requests_dir}/idor_raw_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(all_requests, f, indent=2)
        
        # Save as CSV for easier analysis
        csv_file = f"{self.raw_requests_dir}/idor_raw_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if all_requests:
            df = pd.DataFrame(all_requests)
            df.to_csv(csv_file, index=False)
            
            logger.info(f"Saved {len(all_requests)} requests to {json_file} and {csv_file}")
        else:
            logger.warning("No requests to save")
    
    def create_labeled_dataset(self) -> pd.DataFrame:
        """Create clean, labeled dataset for ML training."""
        logger.info("Creating labeled dataset...")
        
        # Combine all data
        all_data = self.collected_requests + self.test_results
        
        if not all_data:
            logger.warning("No data available for dataset creation")
            return pd.DataFrame()
        
        df = pd.DataFrame(all_data)
        
        # Clean and normalize data
        df = self._clean_dataset(df)
        
        logger.info(f"Created labeled dataset with {len(df)} records")
        logger.info(f"Authorized access records: {len(df[df['is_unauthorized'] == 0])}")
        logger.info(f"Unauthorized access records: {len(df[df['is_unauthorized'] == 1])}")
        
        return df
    
    def _clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize dataset."""
        logger.info("Cleaning and normalizing dataset...")
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['user_id', 'target_id', 'endpoint', 'method'])
        
        # Remove incomplete entries
        df = df.dropna(subset=['status_code', 'response_length', 'is_unauthorized'])
        
        # Standardize endpoint patterns
        df['endpoint_pattern'] = df['endpoint'].apply(self._standardize_endpoint)
        
        # Normalize categorical variables
        df['method_encoded'] = pd.Categorical(df['method']).codes
        df['endpoint_encoded'] = pd.Categorical(df['endpoint_pattern']).codes
        
        # Extract parameter from endpoint
        df['parameter'] = df['endpoint'].apply(self._extract_parameter)
        
        # Select final columns for dataset
        final_columns = [
            'request_id', 'endpoint', 'endpoint_pattern', 'method', 'method_encoded',
            'parameter', 'user_id', 'target_id', 'status_code', 'response_length',
            'sensitive_data_found', 'is_unauthorized', 'response_time', 'timestamp'
        ]
        
        # Ensure all columns exist
        for col in final_columns:
            if col not in df.columns:
                df[col] = 0 if col in ['method_encoded', 'endpoint_encoded', 'sensitive_data_found'] else ''
        
        return df[final_columns]
    
    def _standardize_endpoint(self, endpoint: str) -> str:
        """Standardize endpoint pattern."""
        # Replace IDs with placeholders
        import re
        standardized = re.sub(r'\d+', '<ID>', endpoint)
        standardized = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '<UUID>', standardized)
        return standardized
    
    def _extract_parameter(self, endpoint: str) -> str:
        """Extract parameter name from endpoint."""
        if '?' in endpoint:
            return endpoint.split('?')[1].split('=')[0] if '=' in endpoint else 'id'
        elif '/' in endpoint:
            parts = endpoint.split('/')
            return parts[-1] if parts[-1] != '' else 'id'
        return 'id'
    
    def generate_data_summary(self, df: pd.DataFrame) -> Dict:
        """Generate comprehensive data summary."""
        logger.info("Generating data summary...")
        
        summary = {
            "dataset_info": {
                "total_records": len(df),
                "created_at": datetime.now().isoformat(),
                "data_source": "IDOR Detection System"
            },
            "access_distribution": {
                "authorized_access": len(df[df['is_unauthorized'] == 0]),
                "unauthorized_access": len(df[df['is_unauthorized'] == 1]),
                "unauthorized_percentage": (len(df[df['is_unauthorized'] == 1]) / len(df) * 100) if len(df) > 0 else 0
            },
            "status_code_distribution": df['status_code'].value_counts().to_dict() if len(df) > 0 else {},
            "method_distribution": df['method'].value_counts().to_dict() if len(df) > 0 else {},
            "endpoint_patterns": df['endpoint_pattern'].value_counts().head(10).to_dict() if len(df) > 0 else {},
            "response_stats": {
                "avg_response_length": df['response_length'].mean() if len(df) > 0 else 0,
                "avg_response_time": df['response_time'].mean() if len(df) > 0 else 0,
                "sensitive_data_found": len(df[df['sensitive_data_found'] == 1]) if len(df) > 0 else 0
            },
            "quality_metrics": {
                "completeness": (len(df.dropna()) / len(df) * 100) if len(df) > 0 else 100,
                "duplicate_records": len(df) - len(df.drop_duplicates()),
                "test_coverage": len(df['endpoint_pattern'].unique()) if len(df) > 0 else 0
            }
        }
        
        return summary
    
    def run_full_detection_cycle(self) -> Tuple[pd.DataFrame, Dict]:
        """Run complete IDOR detection cycle."""
        logger.info("Starting full IDOR detection cycle...")
        
        try:
            # Setup test environment
            self.setup_test_users()
            
            # Collect authorized requests
            self.collect_authorized_requests()
            
            # Test unauthorized access scenarios
            self.test_unauthorized_access_scenarios()
            
            # Save raw requests
            self.save_raw_requests()
            
            # Create labeled dataset
            dataset = self.create_labeled_dataset()
            
            # Generate summary
            summary = self.generate_data_summary(dataset)
            
            logger.info("IDOR detection cycle completed successfully")
            
            return dataset, summary
            
        except Exception as e:
            logger.error(f"IDOR detection cycle failed: {e}")
            raise

def main():
    """Main function to run IDOR detection system."""
    logger.info("Starting IDOR Detection System...")
    
    # Initialize system
    idor_system = IDORDetectionSystem(
        base_url="http://localhost:5002",
        output_dir="data"
    )
    
    try:
        # Run full detection cycle
        dataset, summary = idor_system.run_full_detection_cycle()
        
        # Save dataset
        dataset_path = "data/idor_dataset.csv"
        dataset.to_csv(dataset_path, index=False)
        logger.info(f"Saved IDOR dataset to {dataset_path}")
        
        # Save summary report
        summary_path = "docs/idor_data_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Saved data summary to {summary_path}")
        
        # Print summary
        print("\n" + "="*60)
        print("IDOR DETECTION SUMMARY")
        print("="*60)
        print(f"Total Records: {summary['dataset_info']['total_records']}")
        print(f"Authorized Access: {summary['access_distribution']['authorized_access']}")
        print(f"Unauthorized Access: {summary['access_distribution']['unauthorized_access']}")
        print(f"Unauthorized Percentage: {summary['access_distribution']['unauthorized_percentage']:.2f}%")
        print(f"Average Response Time: {summary['response_stats']['avg_response_time']:.3f}s")
        print(f"Sensitive Data Found: {summary['response_stats']['sensitive_data_found']}")
        print("="*60)
        
    except Exception as e:
        logger.error(f"IDOR detection system failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())