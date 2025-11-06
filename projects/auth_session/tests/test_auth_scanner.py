"""
Unit tests for Authentication & Session Security Scanner.
"""

import unittest
import os
import sys
import tempfile
import shutil
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add parent directories to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "projects", "auth_session"))

from scanner.auth_scanner import AuthScanner, EventTracker
from scanner.core import (
    hash_value, anonymize_ip, anonymize_username, anonymize_session_id,
    generate_event_id, parse_auth_result
)
from scanner.config import VALID_USERS, INVALID_PASSWORDS


class TestCoreFunctions(unittest.TestCase):
    """Test core utility functions."""
    
    def test_hash_value(self):
        """Test hash_value function."""
        result = hash_value("test")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 16)
        
        # Same input produces same hash
        result2 = hash_value("test")
        self.assertEqual(result, result2)
        
        # Different input produces different hash
        result3 = hash_value("test2")
        self.assertNotEqual(result, result3)
        
    def test_anonymize_ip(self):
        """Test IP anonymization."""
        ip = "192.168.1.100"
        anonymized = anonymize_ip(ip)
        self.assertIsInstance(anonymized, str)
        self.assertEqual(len(anonymized), 16)
        self.assertNotEqual(ip, anonymized)
        
        # Same IP produces same hash
        anonymized2 = anonymize_ip(ip)
        self.assertEqual(anonymized, anonymized2)
        
    def test_anonymize_username(self):
        """Test username anonymization."""
        username = "testuser"
        anonymized = anonymize_username(username)
        self.assertIsInstance(anonymized, str)
        self.assertEqual(len(anonymized), 16)
        
    def test_generate_event_id(self):
        """Test event ID generation."""
        event_id = generate_event_id()
        self.assertIsInstance(event_id, str)
        self.assertGreater(len(event_id), 0)
        
        # Generate multiple IDs - should be unique
        ids = [generate_event_id() for _ in range(10)]
        self.assertEqual(len(ids), len(set(ids)))
        
    def test_parse_auth_result(self):
        """Test authentication result parsing."""
        # Success
        result, reason = parse_auth_result(200, "admin", VALID_USERS)
        self.assertEqual(result, "success")
        self.assertIsNone(reason)
        
        # Failure - bad password
        result, reason = parse_auth_result(401, "admin", VALID_USERS)
        self.assertEqual(result, "failure")
        self.assertEqual(reason, "bad_password")
        
        # Failure - invalid user
        result, reason = parse_auth_result(401, "nonexistent", VALID_USERS)
        self.assertEqual(result, "failure")
        self.assertEqual(reason, "invalid_user")
        
        # Locked
        result, reason = parse_auth_result(423, "admin", VALID_USERS)
        self.assertEqual(result, "locked")
        self.assertEqual(reason, "locked")
        
        # Rate limited
        result, reason = parse_auth_result(429, "admin", VALID_USERS)
        self.assertEqual(result, "rate_limited")
        self.assertEqual(reason, "rate_limited")


class TestEventTracker(unittest.TestCase):
    """Test EventTracker class."""
    
    def setUp(self):
        self.tracker = EventTracker()
        
    def test_add_event(self):
        """Test adding events to tracker."""
        event = {
            "username_anon": "user1_hash",
            "ip_address_anon": "ip1_hash",
            "timestamp": datetime.now(),
            "endpoint": "/login"
        }
        
        self.tracker.add_event(event)
        self.assertGreater(len(self.tracker.events_by_username), 0)
        self.assertGreater(len(self.tracker.events_by_ip), 0)
        
    def test_count_attempts_for_username(self):
        """Test counting attempts for username."""
        username = "user1_hash"
        
        # Add some events
        for i in range(5):
            event = {
                "username_anon": username,
                "ip_address_anon": "ip1_hash",
                "timestamp": datetime.now(),
                "endpoint": "/login"
            }
            self.tracker.add_event(event)
            
        count = self.tracker.count_attempts_for_username(username, 600)
        self.assertGreaterEqual(count, 5)


class TestAuthScanner(unittest.TestCase):
    """Test AuthScanner class."""
    
    def setUp(self):
        # Use a mock URL for testing
        self.scanner = AuthScanner(base_url="http://test.local/login.php")
        
    def test_init(self):
        """Test scanner initialization."""
        self.assertIsNotNone(self.scanner.tracker)
        self.assertEqual(len(self.scanner.dataset_rows), 0)
        self.assertGreater(len(self.scanner.valid_users), 0)
        self.assertGreater(len(self.scanner.invalid_passwords), 0)
        
    @patch('scanner.auth_scanner.make_http_request')
    def test_simulate_login_success(self, mock_request):
        """Test successful login simulation."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies = {"PHPSESSID": "test_session_123"}
        mock_request.return_value = (mock_response, 200, None)
        
        event = self.scanner.simulate_login("admin", "password", "192.168.1.100")
        
        self.assertEqual(event["auth_result"], "success")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["password_correct_flag"], 1)
        self.assertIsNotNone(event["session_id"])
        
    @patch('scanner.auth_scanner.make_http_request')
    def test_simulate_login_failure(self, mock_request):
        """Test failed login simulation."""
        # Mock failed response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.cookies = {}
        mock_request.return_value = (mock_response, 401, None)
        
        event = self.scanner.simulate_login("admin", "wrongpassword", "192.168.1.100")
        
        self.assertEqual(event["auth_result"], "failure")
        self.assertEqual(event["status_code"], 401)
        self.assertEqual(event["password_correct_flag"], 0)
        
    def test_apply_labeling_heuristics(self):
        """Test labeling heuristics."""
        # Normal event
        normal_event = {
            "username_anon": "user1_hash",
            "ip_address_anon": "ip1_hash",
            "attempt_count_for_username": 2,
            "attempt_count_from_ip": 3,
            "status_code": 200,
            "auth_result": "success"
        }
        
        labeled = self.scanner.apply_labeling_heuristics(normal_event)
        self.assertEqual(labeled["is_bruteforce_candidate"], 0)
        self.assertEqual(labeled["is_anomalous"], 0)
        
        # Brute-force candidate
        bf_event = {
            "username_anon": "user1_hash",
            "ip_address_anon": "ip1_hash",
            "attempt_count_for_username": 15,
            "attempt_count_from_ip": 3,
            "status_code": 401,
            "auth_result": "failure"
        }
        
        labeled = self.scanner.apply_labeling_heuristics(bf_event)
        self.assertEqual(labeled["is_bruteforce_candidate"], 1)
        self.assertEqual(labeled["is_anomalous"], 1)
        
    def test_anonymize_username(self):
        """Test username anonymization in scanner."""
        username = "testuser"
        anonymized = self.scanner.anonymize_username(username)
        
        self.assertIsInstance(anonymized, str)
        self.assertEqual(len(anonymized), 16)
        
        # Same username should produce same hash
        anonymized2 = self.scanner.anonymize_username(username)
        self.assertEqual(anonymized, anonymized2)


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    def test_end_to_end_without_server(self):
        """Test scanner without actual server (mocked requests)."""
        scanner = AuthScanner(base_url="http://test.local/login.php")
        
        # This will fail connection but should handle gracefully
        with patch('scanner.auth_scanner.make_http_request') as mock_request:
            mock_request.return_value = (None, 0, "Connection error")
            
            event = scanner.simulate_login("admin", "password")
            
            # Should still create event with error handling
            self.assertIsNotNone(event)
            self.assertEqual(event["status_code"], 0)


if __name__ == "__main__":
    unittest.main()

