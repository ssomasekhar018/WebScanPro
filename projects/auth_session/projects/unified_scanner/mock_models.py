"""
Mock models for testing the unified scanner without real ML/DL models.
These models simulate the behavior of real models for testing purposes.
"""

import os
import json
import random
import logging

logger = logging.getLogger(__name__)

class MockXSSModel:
    """Mock model for XSS detection."""
    
    def __init__(self):
        """Initialize the mock XSS model."""
        self.xss_patterns = [
            "<script>", "javascript:", "onerror=", "onload=", 
            "eval(", "document.cookie", "alert(", "prompt(", 
            "iframe", "fromcharcode", "\\x", "&#", "onclick="
        ]
        logger.info("Initialized MockXSSModel")
        
    def predict(self, text):
        """Simulate XSS prediction based on simple pattern matching."""
        text = str(text).lower()
        
        # Check for XSS patterns
        pattern_matches = sum(1 for pattern in self.xss_patterns if pattern.lower() in text)
        
        # Calculate probability based on pattern matches
        if pattern_matches > 0:
            # More matches = higher probability
            probability = min(0.5 + (pattern_matches * 0.1), 0.99)
            is_malicious = probability > 0.75
        else:
            # Random low probability for non-matches
            probability = random.uniform(0.01, 0.3)
            is_malicious = False
            
        logger.info(f"XSS prediction: {is_malicious} (prob: {probability:.4f})")
        return {"is_malicious": is_malicious, "probability": probability}
        
    def predict_xss(self, text):
        """Interface method to match the real XSS detector."""
        result = self.predict(text)
        return result["is_malicious"], result["probability"]


class MockSQLiModel:
    """Mock SQL Injection detection model for testing."""
    
    def __init__(self):
        self.name = "MockSQLiModel"
        logger.info(f"Initialized {self.name}")
        
        # Common SQLi patterns to detect
        self.sqli_patterns = [
            "union select", "or 1=1", "' or '", "-- ", "/*", "*/", 
            "drop table", "delete from", "insert into", "exec(", 
            "xp_cmdshell", "information_schema", "sleep(", "waitfor delay"
        ]
    
    def predict(self, request, response):
        """Simulate SQLi prediction based on simple pattern matching."""
        request_str = str(request).lower()
        response_str = str(response).lower()
        
        # Check for SQLi patterns in request
        req_pattern_matches = sum(1 for pattern in self.sqli_patterns if pattern.lower() in request_str)
        
        # Check for error messages in response that might indicate SQLi vulnerability
        error_patterns = ["sql syntax", "mysql error", "syntax error", "unclosed quotation mark"]
        resp_pattern_matches = sum(1 for pattern in error_patterns if pattern in response_str)
        
        # Calculate probability based on pattern matches
        total_matches = req_pattern_matches + (resp_pattern_matches * 2)  # Response matches weighted more
        
        if total_matches > 0:
            # More matches = higher probability
            probability = min(0.5 + (total_matches * 0.1), 0.99)
            is_malicious = probability > 0.7
        else:
            # Random low probability for non-matches
            probability = random.uniform(0.01, 0.3)
            is_malicious = False
            
        logger.info(f"SQLi prediction: {is_malicious} (prob: {probability:.4f})")
        return {"is_malicious": is_malicious, "probability": probability}


# Factory functions to get model instances
def get_mock_xss_model():
    """Get a mock XSS model instance."""
    return MockXSSModel()

def get_mock_sqli_model():
    """Get a mock SQLi model instance."""
    return MockSQLiModel()