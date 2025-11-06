#!/usr/bin/env python3
"""
Simple latency test for ML integration
"""

import requests
import json
import time
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FLASK_URL = "http://127.0.0.1:5000/predict"

def test_latency():
    """Test single request latency"""
    test_data = {
        'event_id': 'latency_test_001',
        'timestamp': datetime.now().isoformat(),
        'username': 'test_user_latency',
        'username_anon': 'test_user_latency',
        'ip_address': '192.168.1.100',
        'ip_address_anon': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'endpoint': '/login',
        'method': 'POST',
        'status_code': 200,
        'auth_result': 'success',
        'failure_reason': '',
        'session_id': 'latency_session_001',
        'password_correct_flag': 1,
        'attempt_count_for_username': 1,
        'attempt_count_from_ip': 1,
        'time_since_last_attempt_for_username': 0
    }
    
    try:
        # Warm up request
        logger.info("Sending warm-up request...")
        requests.post(FLASK_URL, json=test_data, timeout=10)
        
        # Actual test
        logger.info("Sending test request...")
        start_time = time.time()
        response = requests.post(FLASK_URL, json=test_data, timeout=10)
        latency_ms = (time.time() - start_time) * 1000
        
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Latency: {latency_ms:.2f}ms")
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"Result: {result}")
            return latency_ms
        else:
            logger.error(f"Request failed: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Request error: {str(e)}")
        return None

if __name__ == "__main__":
    latency = test_latency()
    if latency:
        logger.info(f"✓ Test completed. Latency: {latency:.2f}ms")
        if latency < 150:
            logger.info("✓ Latency requirement met!")
        else:
            logger.info("✗ Latency requirement not met (needs <150ms)")
    else:
        logger.info("✗ Test failed")