#!/usr/bin/env python3
"""
Comprehensive IDOR Scanner for testing multiple vulnerable applications.
Tests DVWA, OWASP Juice Shop, and bWAPP for IDOR vulnerabilities.
"""

import requests
import json
import pandas as pd
import numpy as np
import joblib
import datetime
import os
import random
from urllib.parse import urljoin, urlparse
import time

# Load the IDOR model
pipeline = joblib.load('ml/idor_model.joblib')

# Configuration for different applications
APPLICATIONS = {
    'DVWA': {
        'base_url': 'http://localhost',
        'login_url': '/login.php',
        'user_profile_url': '/vulnerabilities/brute/',
        'login_required': True,
        'csrf_token': True
    },
    'Juice_Shop': {
        'base_url': 'http://localhost:3000',
        'login_url': '/rest/user/login',
        'user_profile_url': '/profile',
        'login_required': True,
        'api_based': True
    },
    'Mock_Server': {
        'base_url': 'http://localhost:5000',
        'login_url': None,
        'user_profile_url': '/user/profile',
        'login_required': False,
        'simple_headers': True
    }
}

class IDORScanner:
    def __init__(self, app_name, config):
        self.app_name = app_name
        self.config = config
        self.session = requests.Session()
        self.results = []
        self.session_start_time = datetime.datetime.now()
        
    def log_message(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {self.app_name}: {message}")
        
    def extract_features(self, response, user_id, target_id, original_user_id):
        """Extract features from the response for ML model"""
        features = {
            'param_key_count': 1,  # Simplified for now
            'self_access': 1 if user_id == target_id else 0,
            'param_change_rate': 0.5,  # Simplified
            'status_code_cat': 0 if response.status_code == 200 else 1,
            'response_length': len(response.text),
            'sensitive_data_found': 1 if len(response.text) > 50 else 0,
            'is_unauthorized': 1 if user_id != original_user_id else 0
        }
        return features
    
    def predict_idor(self, features):
        """Use ML model to predict IDOR"""
        df = pd.DataFrame([features])
        df_for_prediction = df.drop(columns=["is_unauthorized"], errors="ignore")
        
        prediction = pipeline.predict(df_for_prediction)[0]
        probability = pipeline.predict_proba(df_for_prediction)[0][1]
        
        return {
            "prediction": prediction,
            "probability": probability,
            "label": "anomalous" if prediction == 1 else "normal"
        }
    
    def test_dvwa(self):
        """Test DVWA for IDOR vulnerabilities"""
        self.log_message("Testing DVWA application...")
        
        # Test different user IDs and resource IDs
        test_cases = [
            ("admin", "1", "admin"),      # Own resource
            ("admin", "2", "admin"),      # Own resource  
            ("admin", "1", "user"),       # Cross-user access
            ("admin", "2", "user"),       # Cross-user access
        ]
        
        for user_id, target_id, original_user in test_cases:
            try:
                # Test profile access pattern
                url = urljoin(self.config['base_url'], f"/vulnerabilities/brute/?user_id={target_id}")
                response = self.session.get(url, timeout=10)
                
                features = self.extract_features(response, user_id, target_id, original_user)
                ml_result = self.predict_idor(features)
                
                result = {
                    'application': 'DVWA',
                    'test_type': 'profile_access',
                    'user_id': user_id,
                    'target_id': target_id,
                    'original_user': original_user,
                    'url': url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'ml_prediction': ml_result['prediction'],
                    'ml_probability': ml_result['probability'],
                    'ml_label': ml_result['label'],
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.results.append(result)
                self.log_message(f"Test completed: {user_id} -> {target_id} (Status: {response.status_code}, ML: {ml_result['label']})")
                
            except Exception as e:
                self.log_message(f"Error testing DVWA: {str(e)}")
                
            time.sleep(0.5)  # Rate limiting
    
    def test_juice_shop(self):
        """Test Juice Shop for IDOR vulnerabilities"""
        self.log_message("Testing Juice Shop application...")
        
        # Test different user scenarios
        test_cases = [
            ("demo@demo.com", "1", "demo@demo.com"),
            ("demo@demo.com", "2", "demo@demo.com"), 
            ("demo@demo.com", "1", "admin@juice-sh.op"),
            ("demo@demo.com", "2", "admin@juice-sh.op"),
        ]
        
        for user_id, target_id, original_user in test_cases:
            try:
                # Test profile access
                url = urljoin(self.config['base_url'], f"/rest/user/{target_id}")
                response = self.session.get(url, timeout=10)
                
                features = self.extract_features(response, user_id, target_id, original_user)
                ml_result = self.predict_idor(features)
                
                result = {
                    'application': 'Juice_Shop',
                    'test_type': 'api_user_access',
                    'user_id': user_id,
                    'target_id': target_id,
                    'original_user': original_user,
                    'url': url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'ml_prediction': ml_result['prediction'],
                    'ml_probability': ml_result['probability'],
                    'ml_label': ml_result['label'],
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.results.append(result)
                self.log_message(f"Test completed: {user_id} -> {target_id} (Status: {response.status_code}, ML: {ml_result['label']})")
                
            except Exception as e:
                self.log_message(f"Error testing Juice Shop: {str(e)}")
                
            time.sleep(0.5)
    
    def test_mock_server(self):
        """Test the mock server for IDOR vulnerabilities"""
        self.log_message("Testing Mock Server application...")
        
        # Test cases similar to the training data
        test_cases = [
            ("user_a", "101", "user_a"),  # Own resource
            ("user_a", "102", "user_a"),  # Own resource
            ("user_a", "201", "user_b"),  # Cross-user access
            ("user_a", "202", "user_b"),  # Cross-user access
            ("user_b", "201", "user_b"),  # Own resource
            ("user_b", "202", "user_b"),  # Own resource
            ("user_b", "101", "user_a"),  # Cross-user access
            ("user_b", "102", "user_a"),  # Cross-user access
        ]
        
        for user_id, target_id, original_user in test_cases:
            try:
                url = urljoin(self.config['base_url'], f"/user/profile?id={target_id}")
                headers = {"X-User-ID": user_id}
                response = self.session.get(url, headers=headers, timeout=10)
                
                features = self.extract_features(response, user_id, target_id, original_user)
                ml_result = self.predict_idor(features)
                
                result = {
                    'application': 'Mock_Server',
                    'test_type': 'profile_access',
                    'user_id': user_id,
                    'target_id': target_id,
                    'original_user': original_user,
                    'url': url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'ml_prediction': ml_result['prediction'],
                    'ml_probability': ml_result['probability'],
                    'ml_label': ml_result['label'],
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.results.append(result)
                self.log_message(f"Test completed: {user_id} -> {target_id} (Status: {response.status_code}, ML: {ml_result['label']})")
                
            except Exception as e:
                self.log_message(f"Error testing Mock Server: {str(e)}")
                
            time.sleep(0.5)
    
    def run_scan(self):
        """Run the comprehensive scan"""
        self.log_message("Starting comprehensive IDOR scan...")
        
        # Run tests based on application type
        if self.app_name == 'DVWA':
            self.test_dvwa()
        elif self.app_name == 'Juice_Shop':
            self.test_juice_shop()
        elif self.app_name == 'Mock_Server':
            self.test_mock_server()
        
        self.log_message(f"Scan completed. Total tests: {len(self.results)}")
        return self.results
    
    def save_results(self, filename=None):
        """Save scan results to CSV file"""
        # Ensure output directory exists
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{output_dir}/{self.app_name.lower()}_scan_results_{timestamp}.csv"
        
        if self.results:
            df = pd.DataFrame(self.results)
            df.to_csv(filename, index=False)
            self.log_message(f"Results saved to {filename}")
        else:
            self.log_message("No results to save")
        
        return filename

def main():
    """Main function to run scans on all applications"""
    all_results = []
    
    # Create output directory if it doesn't exist
    os.makedirs('output', exist_ok=True)
    
    for app_name, config in APPLICATIONS.items():
        try:
            scanner = IDORScanner(app_name, config)
            results = scanner.run_scan()
            scanner.save_results()
            
            all_results.extend(results)
            
        except Exception as e:
            print(f"Error scanning {app_name}: {str(e)}")
    
    # Save combined results
    if all_results:
        combined_df = pd.DataFrame(all_results)
        combined_filename = f"output/comprehensive_idor_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        combined_df.to_csv(combined_filename, index=False)
        print(f"All results saved to {combined_filename}")
        
        # Generate summary statistics
        print("\n=== SCAN SUMMARY ===")
        print(f"Total tests run: {len(all_results)}")
        
        for app in APPLICATIONS.keys():
            app_results = [r for r in all_results if r['application'] == app]
            if app_results:
                anomalous_count = sum(1 for r in app_results if r['ml_label'] == 'anomalous')
                print(f"{app}: {len(app_results)} tests, {anomalous_count} anomalous")
    
    return all_results

if __name__ == "__main__":
    main()