#!/usr/bin/env python3
"""
Latency test for ultra-fast ML integration server
"""

import requests
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test data
TEST_DATA = {
    "session_id": "latency_session_001",
    "login_rate": 0.5,
    "session_duration": 1800,
    "failed_login_rate": 0.1,
    "device_change_rate": 0.2,
    "location_change_rate": 0.1,
    "time_since_last_login": 3600,
    "avg_login_interval": 7200,
    "failed_login_ratio": 0.2,
    "device_diversity": 2,
    "location_diversity": 1,
    "hour_of_day": 14,
    "day_of_week": 3,
    "is_weekend": 0,
    "is_business_hours": 1,
    "is_night_hours": 0,
    "login_count_24h": 5,
    "failed_count_24h": 1,
    "device_count_24h": 2,
    "location_count_24h": 1,
    "max_login_rate_24h": 1.0
}

def test_latency():
    """Test latency of ultra-fast server"""
    url = "http://127.0.0.1:5001/predict"
    
    logger.info("Sending warm-up request...")
    try:
        response = requests.post(url, json=TEST_DATA, timeout=5)
        logger.info(f"Warm-up response: {response.status_code}")
    except Exception as e:
        logger.error(f"Warm-up failed: {e}")
        return
    
    logger.info("Sending test request...")
    start_time = time.time()
    
    try:
        response = requests.post(url, json=TEST_DATA, timeout=5)
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Latency: {latency:.2f}ms")
            logger.info(f"Result: {result}")
            
            if latency < 150:
                logger.info("✓ Latency requirement met!")
            else:
                logger.info("✗ Latency requirement not met (needs <150ms)")
                
        else:
            logger.error(f"Request failed with status: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    test_latency()