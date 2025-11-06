#!/usr/bin/env python3
"""
Integration Test Suite for ML Authentication Scanner
Tests the complete end-to-end ML integration pipeline
"""

import requests
import json
import time
import pandas as pd
import logging
from datetime import datetime
import numpy as np
import sys
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('output/integration_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
FLASK_URL = "http://127.0.0.1:5000/predict"
FASTAPI_URL = "http://127.0.0.1:8000/predict"
TEST_DATA_FILE = "data/feature_dataset.csv"
OUTPUT_FILE = "output/test_integration_results.csv"
MAX_LATENCY_MS = 150  # Maximum allowed latency in milliseconds

def test_flask_endpoint():
    """Test Flask ML integration endpoint"""
    logger.info("Testing Flask ML integration endpoint...")
    
    # Sample test data
    test_data = {
        'event_id': 'test_event_001',
        'timestamp': datetime.now().isoformat(),
        'username': 'test_user_123',
        'username_anon': 'test_user_123',
        'ip_address': '192.168.1.100',
        'ip_address_anon': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'endpoint': '/login',
        'method': 'POST',
        'status_code': 200,
        'auth_result': 'success',
        'failure_reason': '',
        'session_id': 'test_session_001',
        'password_correct_flag': 1,
        'attempt_count_for_username': 1,
        'attempt_count_from_ip': 1,
        'time_since_last_attempt_for_username': 0
    }
    
    try:
        start_time = time.time()
        response = requests.post(FLASK_URL, json=test_data, timeout=10)
        latency_ms = (time.time() - start_time) * 1000
        
        logger.info(f"Flask Response Status: {response.status_code}")
        logger.info(f"Flask Response Time: {latency_ms:.2f}ms")
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"Flask Response Data: {json.dumps(result, indent=2)}")
            
            # Validate response structure
            required_fields = ['session_id', 'iforest_score', 'autoencoder_error', 'final_label']
            if all(field in result for field in required_fields):
                logger.info("✓ Flask endpoint validation passed")
                return True, latency_ms, result
            else:
                logger.error(f"✗ Flask response missing required fields: {result}")
                return False, latency_ms, result
        else:
            logger.error(f"✗ Flask endpoint failed: {response.status_code}")
            return False, latency_ms, None
            
    except Exception as e:
        logger.error(f"✗ Flask endpoint error: {str(e)}")
        return False, 0, None

def test_fastapi_endpoint():
    """Test FastAPI ML integration endpoint"""
    logger.info("Testing FastAPI ML integration endpoint...")
    
    # Sample test data
    test_data = {
        'event_id': 'test_event_002',
        'timestamp': datetime.now().isoformat(),
        'username': 'test_user_456',
        'username_anon': 'test_user_456',
        'ip_address': '192.168.1.101',
        'ip_address_anon': '192.168.1.101',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'endpoint': '/login',
        'method': 'POST',
        'status_code': 401,
        'auth_result': 'failure',
        'failure_reason': 'invalid_password',
        'session_id': 'test_session_002',
        'password_correct_flag': 0,
        'attempt_count_for_username': 3,
        'attempt_count_from_ip': 5,
        'time_since_last_attempt_for_username': 60
    }
    
    try:
        start_time = time.time()
        response = requests.post(FASTAPI_URL, json=test_data, timeout=10)
        latency_ms = (time.time() - start_time) * 1000
        
        logger.info(f"FastAPI Response Status: {response.status_code}")
        logger.info(f"FastAPI Response Time: {latency_ms:.2f}ms")
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"FastAPI Response Data: {json.dumps(result, indent=2)}")
            
            # Validate response structure
            if 'predictions' in result and 'ensemble_prediction' in result:
                logger.info("✓ FastAPI endpoint validation passed")
                return True, latency_ms, result
            else:
                logger.error(f"✗ FastAPI response missing required fields: {result}")
                return False, latency_ms, result
        else:
            logger.error(f"✗ FastAPI endpoint failed: {response.status_code}")
            return False, latency_ms, None
            
    except Exception as e:
        logger.error(f"✗ FastAPI endpoint error: {str(e)}")
        return False, 0, None

def load_test_data():
    """Load test data from dataset"""
    try:
        df = pd.read_csv(TEST_DATA_FILE)
        logger.info(f"Loaded {len(df)} test samples from {TEST_DATA_FILE}")
        return df
    except Exception as e:
        logger.error(f"Failed to load test data: {str(e)}")
        return None

def run_performance_tests():
    """Run performance and latency tests"""
    logger.info("Running performance tests...")
    
    # Load test data
    test_df = load_test_data()
    if test_df is None or len(test_df) == 0:
        logger.error("No test data available for performance testing")
        return None
    
    results = []
    
    # Test with first 20 samples
    sample_size = min(20, len(test_df))
    test_samples = test_df.head(sample_size)
    
    for i, (_, row) in enumerate(test_samples.iterrows()):
        logger.info(f"Testing sample {i+1}/{sample_size}")
        
        # Prepare test data
        test_data = row.to_dict()
        test_data['event_id'] = f'perf_test_{i+1}'
        test_data['timestamp'] = datetime.now().isoformat()
        
        try:
            start_time = time.time()
            response = requests.post(FLASK_URL, json=test_data, timeout=10)
            latency_ms = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                result = response.json()
                results.append({
                    'sample_id': i+1,
                    'latency_ms': latency_ms,
                    'iforest_score': result.get('iforest_score', 0),
                    'autoencoder_error': result.get('autoencoder_error', 0),
                    'final_label': result.get('final_label', 'unknown'),
                    'status_code': response.status_code,
                    'success': True
                })
            else:
                results.append({
                    'sample_id': i+1,
                    'latency_ms': latency_ms,
                    'iforest_score': 0,
                    'autoencoder_error': 0,
                    'final_label': 'error',
                    'status_code': response.status_code,
                    'success': False
                })
                
        except Exception as e:
            logger.error(f"Performance test error for sample {i+1}: {str(e)}")
            results.append({
                'sample_id': i+1,
                'latency_ms': 0,
                'iforest_score': 0,
                'autoencoder_error': 0,
                'final_label': 'error',
                'status_code': 0,
                'success': False
            })
    
    return results

def generate_test_report(flake_results, fastapi_results, performance_results):
    """Generate comprehensive test report"""
    logger.info("Generating test report...")
    
    report = {
        'test_timestamp': datetime.now().isoformat(),
        'flask_test': {
            'success': flake_results[0],
            'latency_ms': flake_results[1],
            'result': flake_results[2]
        },
        'fastapi_test': {
            'success': fastapi_results[0],
            'latency_ms': fastapi_results[1],
            'result': fastapi_results[2]
        },
        'performance_summary': {},
        'latency_requirements': {}
    }
    
    if performance_results:
        df = pd.DataFrame(performance_results)
        
        # Performance summary
        report['performance_summary'] = {
            'total_tests': len(df),
            'successful_tests': df['success'].sum(),
            'failed_tests': len(df) - df['success'].sum(),
            'avg_latency_ms': df['latency_ms'].mean(),
            'min_latency_ms': df['latency_ms'].min(),
            'max_latency_ms': df['latency_ms'].max(),
            'std_latency_ms': df['latency_ms'].std()
        }
        
        # Latency requirements check
        within_limit = (df['latency_ms'] <= MAX_LATENCY_MS).sum()
        report['latency_requirements'] = {
            'max_allowed_latency_ms': MAX_LATENCY_MS,
            'tests_within_limit': within_limit,
            'tests_exceeding_limit': len(df) - within_limit,
            'compliance_percentage': (within_limit / len(df)) * 100
        }
        
        # Save detailed results
        df.to_csv(OUTPUT_FILE, index=False)
        logger.info(f"Detailed results saved to {OUTPUT_FILE}")
    
    # Save report
    report_file = "output/integration_test_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"Test report saved to {report_file}")
    return report

def main():
    """Main integration test function"""
    logger.info("Starting ML Integration Test Suite")
    logger.info("=" * 50)
    
    # Test Flask endpoint
    flask_success, flask_latency, flask_result = test_flask_endpoint()
    
    # Test FastAPI endpoint (if available)
    fastapi_success, fastapi_latency, fastapi_result = test_fastapi_endpoint()
    
    # Run performance tests
    performance_results = run_performance_tests()
    
    # Generate report
    report = generate_test_report(
        (flask_success, flask_latency, flask_result),
        (fastapi_success, fastapi_latency, fastapi_result),
        performance_results
    )
    
    # Print summary
    logger.info("=" * 50)
    logger.info("INTEGRATION TEST SUMMARY")
    logger.info("=" * 50)
    logger.info(f"Flask Integration: {'✓ PASS' if flask_success else '✗ FAIL'}")
    logger.info(f"FastAPI Integration: {'✓ PASS' if fastapi_success else '✗ FAIL'}")
    
    if performance_results:
        perf_summary = report['performance_summary']
        latency_req = report['latency_requirements']
        
        logger.info(f"Performance Tests: {perf_summary['successful_tests']}/{perf_summary['total_tests']} successful")
        logger.info(f"Average Latency: {perf_summary['avg_latency_ms']:.2f}ms")
        logger.info(f"Latency Compliance: {latency_req['compliance_percentage']:.1f}% within {MAX_LATENCY_MS}ms limit")
        
        # Check if all tests passed
        all_passed = (flask_success and 
                     (not fastapi_success or fastapi_success) and  # FastAPI optional
                     perf_summary['successful_tests'] == perf_summary['total_tests'] and
                     latency_req['compliance_percentage'] >= 95)  # 95% compliance threshold
        
        logger.info(f"Overall Result: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
    else:
        logger.info("Performance Tests: No results available")
    
    return 0 if flask_success else 1

if __name__ == "__main__":
    sys.exit(main())