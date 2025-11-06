"""
Core utilities for Authentication & Session Security Scanner.
Shared functions for HTTP requests, anonymization, and event processing.
"""

import time
import hashlib
import hmac
import uuid
import requests
from datetime import datetime
from typing import Dict, Optional
from .config import HASH_SALT, REQUEST_SETTINGS, USER_AGENTS
import random


def hash_value(value: str, salt: bytes = HASH_SALT) -> str:
    """Hash a value using HMAC-SHA256 for anonymization."""
    if not value:
        return ""
    return hmac.new(salt, value.encode('utf-8'), hashlib.sha256).hexdigest()[:16]


def anonymize_ip(ip: str) -> str:
    """Anonymize IP address (hash for privacy while preserving grouping)."""
    return hash_value(ip)


def anonymize_username(username: str) -> str:
    """Anonymize username (hash for privacy while preserving grouping)."""
    return hash_value(username)


def anonymize_session_id(session_id: str) -> str:
    """Anonymize session ID."""
    return hash_value(session_id)


def generate_event_id() -> str:
    """Generate unique event ID."""
    return str(uuid.uuid4())


def get_random_user_agent() -> str:
    """Get random user agent from pool."""
    return random.choice(USER_AGENTS)


def make_http_request(url: str, method: str = "POST", data: Optional[Dict] = None, json: Optional[Dict] = None,
                     headers: Optional[Dict] = None, cookies: Optional[Dict] = None, retries: int = 3, delay: int = 2) -> Optional[requests.Response]:
    """
    Make HTTP request with error handling and retries.
    
    Returns:
        response_object or None
    """
    print(f"Making {method} request to {url} with data: {data} and json: {json}")
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = get_random_user_agent()
        
    for i in range(retries):
        try:
            response = requests.request(
                method=method,
                url=url,
                data=data,
                json=json,
                headers=headers,
                cookies=cookies,
                timeout=30,
                allow_redirects=REQUEST_SETTINGS["allow_redirects"],
                verify=REQUEST_SETTINGS["verify"]
            )
            print(f"Request successful with status code: {response.status_code}")
            return response
        except requests.exceptions.Timeout as e:
            print(f"HTTP request failed: {e}")
            if i < retries - 1:
                time.sleep(delay)
                continue
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"HTTP request failed: {e}")
            if i < retries - 1:
                time.sleep(delay)
                continue
            return None
        except Exception as e:
            print(f"HTTP request failed: {e}")
            return None


def parse_auth_result(status_code: int, username: str, valid_users: list) -> tuple:
    """
    Parse authentication result from status code.
    
    Returns:
        (auth_result, failure_reason)
    """
    if status_code == 200:
        return "success", None
    elif status_code == 401:
        # Check if username exists in valid users
        username_exists = any(u[0] == username for u in valid_users)
        failure_reason = "bad_password" if username_exists else "invalid_user"
        return "failure", failure_reason
    elif status_code == 423:
        return "locked", "locked"
    elif status_code == 429:
        return "rate_limited", "rate_limited"
    else:
        return "failure", "unknown"


def extract_session_id(response) -> Optional[str]:
    """Extract session ID from response cookies."""
    if not response:
        return None
        
    # Common session cookie names
    session_cookies = ["PHPSESSID", "session_id", "sessionId", "JSESSIONID", "session"]
    for cookie_name in session_cookies:
        if cookie_name in response.cookies:
            return response.cookies.get(cookie_name)
    return None


def validate_event(event: Dict) -> tuple:
    """
    Validate event data.
    
    Returns:
        (is_valid, error_message)
    """
    required_fields = ["event_id", "timestamp", "username_anon", "ip_address_anon"]
    
    for field in required_fields:
        if field not in event:
            return False, f"Missing required field: {field}"
            
    # Validate timestamp format
    try:
        datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
    except:
        return False, "Invalid timestamp format"
        
    return True, None

