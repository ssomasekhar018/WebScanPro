"""
Test cases for the unified vulnerability scanner.
"""

import os
import sys
import unittest
import json
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unified_scanner import UnifiedScanner
from inference_xss import get_xss_detector
from inference_sqli import get_sqli_detector


class TestUnifiedScanner(unittest.TestCase):
    """Test cases for the unified vulnerability scanner."""
    
    def setUp(self):
        """Set up test environment."""
        # Mock configuration
        self.config = {
            'output_file': 'test_report.json',
            'threads': 1,
            'timeout': 1,
            'max_payloads': 2,
            'xss_threshold': 0.5,
            'sqli_threshold': 0.5
        }
        
        # Create test URLs
        self.test_urls = [
            'https://testsite.com/login',
            'https://testsite.com/search'
        ]
    
    @patch('projects.unified_scanner.inference_xss.get_xss_detector')
    @patch('projects.unified_scanner.inference_sqli.get_sqli_detector')
    @patch('projects.unified_scanner.unified_scanner.make_request')
    def test_scanner_initialization(self, mock_make_request, mock_sqli_detector, mock_xss_detector):
        """Test scanner initialization."""
        # Mock detector instances
        mock_xss_detector.return_value = MagicMock()
        mock_sqli_detector.return_value = MagicMock()
        
        # Initialize scanner
        scanner = UnifiedScanner(self.config)
        
        # Verify detectors were initialized
        self.assertIsNotNone(scanner.xss_detector)
        self.assertIsNotNone(scanner.sqli_detector)
        
        # Verify reporter was initialized
        self.assertIsNotNone(scanner.reporter)
        self.assertEqual(scanner.reporter.output_file, 'test_report.json')
    
    @patch('projects.unified_scanner.inference_xss.get_xss_detector')
    @patch('projects.unified_scanner.inference_sqli.get_sqli_detector')
    @patch('projects.unified_scanner.unified_scanner.make_request')
    def test_scan_url(self, mock_make_request, mock_sqli_detector, mock_xss_detector):
        """Test scanning a single URL."""
        # Mock response
        mock_response = MagicMock()
        mock_response.text = "<html>Test response</html>"
        mock_make_request.return_value = mock_response
        
        # Mock detectors
        mock_xss = MagicMock()
        mock_xss.predict_xss.return_value = {"prob": 0.8, "label": "malicious"}
        mock_xss_detector.return_value = mock_xss
        
        mock_sqli = MagicMock()
        mock_sqli.predict_sqli.return_value = {"prob": 0.2, "label": "benign"}
        mock_sqli_detector.return_value = mock_sqli
        
        # Initialize scanner
        scanner = UnifiedScanner(self.config)
        
        # Scan URL
        result = scanner.scan_url(self.test_urls[0])
        
        # Verify result
        self.assertIsNotNone(result)
        self.assertEqual(result["url"], self.test_urls[0])
        self.assertTrue(result["xss"]["is_vulnerable"])
        self.assertFalse(result["sqli"]["is_vulnerable"])
    
    @patch('projects.unified_scanner.inference_xss.get_xss_detector')
    @patch('projects.unified_scanner.inference_sqli.get_sqli_detector')
    @patch('projects.unified_scanner.unified_scanner.make_request')
    def test_scan_urls(self, mock_make_request, mock_sqli_detector, mock_xss_detector):
        """Test scanning multiple URLs."""
        # Mock response
        mock_response = MagicMock()
        mock_response.text = "<html>Test response</html>"
        mock_make_request.return_value = mock_response
        
        # Mock detectors
        mock_xss = MagicMock()
        mock_xss.predict_xss.return_value = {"prob": 0.8, "label": "malicious"}
        mock_xss_detector.return_value = mock_xss
        
        mock_sqli = MagicMock()
        mock_sqli.predict_sqli.return_value = {"prob": 0.2, "label": "benign"}
        mock_sqli_detector.return_value = mock_sqli
        
        # Initialize scanner
        scanner = UnifiedScanner(self.config)
        
        # Scan URLs
        results = scanner.scan_urls(self.test_urls)
        
        # Verify results
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["url"], self.test_urls[0])
        self.assertEqual(results[1]["url"], self.test_urls[1])


if __name__ == '__main__':
    unittest.main()