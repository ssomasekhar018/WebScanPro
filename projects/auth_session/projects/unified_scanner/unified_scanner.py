"""
Unified Vulnerability Scanner
Combines XSS and SQLi detection into a single scanning pipeline.
"""

import os
import sys
import json
import logging
import argparse
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

# Import local modules
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from projects.unified_scanner.config import (
    MODEL_PATHS, TOKENIZER_PATHS, THRESHOLDS, 
    SCAN_OPTIONS, get_report_filename, LOG_CONFIG
)
from projects.unified_scanner.inference_xss import get_xss_detector
from projects.unified_scanner.inference_sqli import get_sqli_detector
from projects.unified_scanner.reporting import VulnerabilityReporter
from projects.unified_scanner.utils import (
    setup_logging, make_request, get_xss_payloads, 
    get_sqli_payloads, extract_request_data, extract_response_data
)

class UnifiedScanner:
    def __init__(self, config=None):
        """Initialize the unified scanner with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize detectors
        self.xss_detector = None
        self.sqli_detector = None
        
        # Initialize reporter
        self.reporter = VulnerabilityReporter(
            output_file=self.config.get('output_file', get_report_filename())
        )
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load XSS and SQLi detection models."""
        # Check if we should use mock models
        if self.config.get('use_mock_models', False):
            self.logger.info("Using mock models for testing")
            from projects.unified_scanner.mock_models import get_mock_xss_model, get_mock_sqli_model
            self.xss_detector = get_mock_xss_model()
            self.sqli_detector = get_mock_sqli_model()
            return
            
        try:
            # Try to load real models
            xss_model_path = self.config.get('xss_model_path', MODEL_PATHS['xss'])
            xss_tokenizer_path = self.config.get('xss_tokenizer_path', TOKENIZER_PATHS['xss'])
            
            self.logger.info(f"Loading XSS model from {xss_model_path}")
            self.xss_detector = get_xss_detector(xss_model_path, xss_tokenizer_path)
            
            # Load SQLi model
            sqli_model_path = self.config.get('sqli_model_path', MODEL_PATHS['sqli'])
            sqli_vectorizer_path = self.config.get('sqli_vectorizer_path', TOKENIZER_PATHS['sqli'])
            
            self.logger.info(f"Loading SQLi model from {sqli_model_path}")
            self.sqli_detector = get_sqli_detector(sqli_model_path, sqli_vectorizer_path)
        except Exception as e:
            # Fall back to mock models if real models can't be loaded
            self.logger.warning(f"Failed to load real models: {str(e)}")
            self.logger.info("Falling back to mock models for testing")
            
            from projects.unified_scanner.mock_models import get_mock_xss_model, get_mock_sqli_model
            self.xss_detector = get_mock_xss_model()
            self.sqli_detector = get_mock_sqli_model()
    
    def scan_url(self, url):
        """Scan a single URL for XSS and SQLi vulnerabilities."""
        self.logger.info(f"Scanning URL: {url}")
        
        # Validate URL
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                self.logger.error(f"Invalid URL: {url}")
                return None
        except Exception as e:
            self.logger.error(f"URL parsing error: {str(e)}")
            return None
        
        # Initialize result
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "xss": {
                "is_vulnerable": False,
                "probability": 0.0,
                "payloads_tested": 0,
                "vulnerable_payloads": []
            },
            "sqli": {
                "is_vulnerable": False,
                "probability": 0.0,
                "payloads_tested": 0,
                "vulnerable_payloads": []
            }
        }
        
        # Test XSS vulnerabilities
        self._test_xss_vulnerabilities(url, result)
        
        # Test SQLi vulnerabilities
        self._test_sqli_vulnerabilities(url, result)
        
        # Add result to reporter
        self.reporter.add_result(result)
        
        return result
    
    def _test_xss_vulnerabilities(self, url, result):
        """Test URL for XSS vulnerabilities."""
        xss_payloads = get_xss_payloads(self.config.get('max_payloads', SCAN_OPTIONS['max_payloads']))
        result['xss']['payloads_tested'] = len(xss_payloads)
        
        max_probability = 0.0
        vulnerable_payloads = []
        
        for payload in xss_payloads:
            # Make request with XSS payload
            response = make_request(
                url=url,
                payload={"xss_test": payload},
                method="GET",
                timeout=self.config.get('timeout', SCAN_OPTIONS['timeout']),
                retries=self.config.get('retry_count', SCAN_OPTIONS['retry_count'])
            )
            
            if not response:
                continue
                
            # Extract response text
            response_text = response.text
            
            try:
                # Predict XSS vulnerability using detector
                is_vulnerable, probability = self.xss_detector.predict_xss(response_text)
                
                # Check if vulnerable
                if probability > max_probability:
                    max_probability = probability
                    
                # If probability exceeds threshold, mark as vulnerable
                if is_vulnerable:
                    self.logger.warning(f"XSS vulnerability detected in {url} with probability {probability}")
                    vulnerable_payloads.append({
                        "payload": payload,
                        "probability": probability,
                        "url": url
                    })
            except Exception as e:
                self.logger.error(f"Error in XSS detection: {str(e)}")
                # Use a fallback approach if model fails
                if any(pattern in response_text.lower() for pattern in ["<script>", "javascript:", "onerror=", "alert("]):
                    probability = 0.85  # Default probability for pattern-based detection
                    if probability > max_probability:
                        max_probability = probability
                    vulnerable_payloads.append({
                        "payload": payload,
                        "probability": probability
                    })
        
        # Update result
        result['xss']['probability'] = max_probability
        result['xss']['is_vulnerable'] = max_probability >= self.config.get('xss_threshold', THRESHOLDS['xss'])
        result['xss']['vulnerable_payloads'] = vulnerable_payloads
        
        self.logger.info(f"XSS scan result for {url}: {result['xss']['is_vulnerable']} (prob: {max_probability:.4f})")
    
    def _test_sqli_vulnerabilities(self, url, result):
        """Test URL for SQLi vulnerabilities."""
        sqli_payloads = get_sqli_payloads(self.config.get('max_payloads', SCAN_OPTIONS['max_payloads']))
        result['sqli']['payloads_tested'] = len(sqli_payloads)
        
        max_probability = 0.0
        vulnerable_payloads = []
        
        for payload in sqli_payloads:
            # Make request with SQLi payload
            response = make_request(
                url=url,
                payload={"sqli_test": payload},
                method="GET",
                timeout=self.config.get('timeout', SCAN_OPTIONS['timeout']),
                retries=self.config.get('retry_count', SCAN_OPTIONS['retry_count'])
            )
            
            if not response:
                continue
                
            # Extract request and response data
            request_data = {
                "method": "GET",
                "url": url,
                "payload": payload
            }
            response_data = extract_response_data(response)
            
            try:
                # Predict SQLi vulnerability
                sqli_result = self.sqli_detector.predict_sqli(request_data, response_data)
                
                # Check if vulnerable
                probability = sqli_result.get('prob', 0.0)
                if probability > max_probability:
                    max_probability = probability
                    
                # If probability exceeds threshold, mark as vulnerable
                if probability >= self.config.get('sqli_threshold', THRESHOLDS['sqli']):
                    self.logger.warning(f"SQLi vulnerability detected in {url} with probability {probability}")
                    vulnerable_payloads.append({
                        "payload": payload,
                        "probability": probability,
                        "url": url
                    })
            except Exception as e:
                self.logger.error(f"Error in SQLi detection: {str(e)}")
                # Use a fallback approach if model fails
                response_text = response.text.lower()
                if any(pattern in response_text for pattern in ["sql error", "syntax error", "mysql", "oracle", "sqlite"]):
                    probability = 0.85  # Default probability for pattern-based detection
                    if probability > max_probability:
                        max_probability = probability
                    vulnerable_payloads.append({
                        "payload": payload,
                        "probability": probability,
                        "url": url
                    })
        
        # Update result
        result['sqli']['probability'] = max_probability
        result['sqli']['is_vulnerable'] = max_probability >= self.config.get('sqli_threshold', THRESHOLDS['sqli'])
        result['sqli']['vulnerable_payloads'] = vulnerable_payloads
        
        self.logger.info(f"SQLi scan result for {url}: {result['sqli']['is_vulnerable']} (prob: {max_probability:.4f})")
    
    def scan_urls(self, urls):
        """Scan multiple URLs for vulnerabilities."""
        results = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.get('threads', SCAN_OPTIONS['threads'])
        ) as executor:
            # Submit scanning tasks
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning {url}: {str(e)}")
        
        return results
    
    def scan_from_file(self, file_path):
        """Scan URLs from a file."""
        urls = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        urls.append(url)
        except Exception as e:
            self.logger.error(f"Error reading URL file: {str(e)}")
            return []
        
        return self.scan_urls(urls)
    
    def generate_report(self):
        """Generate and save vulnerability report."""
        # Save JSON report
        self.reporter.save_json_report()
        
        # Save CSV report (optional)
        csv_file = self.config.get('output_file', '').replace('.json', '.csv')
        if csv_file:
            self.reporter.save_csv_report(csv_file)
        
        # Print console summary
        self.reporter.print_console_summary()


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Unified Vulnerability Scanner for XSS and SQLi')
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--url', help='Single URL to scan')
    input_group.add_argument('--url-list', help='File containing URLs to scan (one per line)')
    
    # Output options
    parser.add_argument('--output', help='Output file path for JSON report')
    
    # Scan options
    parser.add_argument('--threads', type=int, default=SCAN_OPTIONS['threads'],
                        help='Number of concurrent scanning threads')
    parser.add_argument('--timeout', type=int, default=SCAN_OPTIONS['timeout'],
                        help='Request timeout in seconds')
    parser.add_argument('--max-payloads', type=int, default=SCAN_OPTIONS['max_payloads'],
                        help='Maximum number of payloads to test per vulnerability type')
    
    # Model options
    parser.add_argument('--xss-model', help='Path to XSS model')
    parser.add_argument('--sqli-model', help='Path to SQLi model')
    parser.add_argument('--xss-threshold', type=float, default=THRESHOLDS['xss'],
                        help='Threshold for XSS detection')
    parser.add_argument('--sqli-threshold', type=float, default=THRESHOLDS['sqli'],
                        help='Threshold for SQLi detection')
    
    return parser.parse_args()


def main():
    """Main entry point for the unified scanner."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(LOG_CONFIG['filename'], LOG_CONFIG['level'])
    logger.info("Starting Unified Vulnerability Scanner")
    
    # Prepare configuration
    config = {
        'output_file': args.output or get_report_filename(),
        'threads': args.threads,
        'timeout': args.timeout,
        'max_payloads': args.max_payloads,
        'xss_model_path': args.xss_model or MODEL_PATHS['xss'],
        'sqli_model_path': args.sqli_model or MODEL_PATHS['sqli'],
        'xss_threshold': args.xss_threshold,
        'sqli_threshold': args.sqli_threshold
    }
    
    # Initialize scanner
    scanner = UnifiedScanner(config)
    
    # Run scan
    if args.url:
        logger.info(f"Scanning single URL: {args.url}")
        scanner.scan_url(args.url)
    elif args.url_list:
        logger.info(f"Scanning URLs from file: {args.url_list}")
        scanner.scan_from_file(args.url_list)
    
    # Generate report
    scanner.generate_report()
    
    logger.info("Scan completed")


if __name__ == "__main__":
    main()