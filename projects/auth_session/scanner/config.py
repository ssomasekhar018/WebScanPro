"""
Configuration file for Authentication & Session Security Scanner.
Contains paths, thresholds, and scan options.
"""

import os
from datetime import datetime

# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
AUTH_SESSION_DIR = os.path.abspath(os.path.join(PROJECT_ROOT, "projects", "auth_session"))

# Directory paths
DATA_DIR = os.path.join(AUTH_SESSION_DIR, "data")
DOCS_DIR = os.path.join(AUTH_SESSION_DIR, "docs")
LOGS_DIR = os.path.join(AUTH_SESSION_DIR, "logs")
SCANNER_DIR = os.path.join(AUTH_SESSION_DIR, "scanner")
ML_DIR = os.path.join(AUTH_SESSION_DIR, "ml")

# Ensure directories exist
for directory in [DATA_DIR, DOCS_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Data files
PATTERNS_CSV = os.path.join(DATA_DIR, "attack_patterns.csv")
DATASET_CSV = os.path.join(DATA_DIR, "login_session_dataset.csv")
FEATURE_DATASET_CSV = os.path.join(DATA_DIR, "feature_dataset.csv")

# Default test endpoints (can be configured via environment)
DEFAULT_LOGIN_URL = os.getenv("AUTH_LOGIN_URL", "http://127.0.0.1:5000/login")
DEFAULT_LOGOUT_URL = os.getenv("AUTH_LOGOUT_URL", "http://127.0.0.1:5000/logout")
DEFAULT_SESSION_REFRESH_URL = os.getenv("AUTH_SESSION_REFRESH_URL", "http://127.0.0.1:5000/session/refresh")

# Security & Anonymization
HASH_SALT = os.getenv("AUTH_HASH_SALT", "auth_dataset_salt_2025").encode('utf-8')

# Rolling window settings (in seconds)
WINDOW_5M = 300   # 5 minutes
WINDOW_10M = 600  # 10 minutes
WINDOW_15M = 900  # 15 minutes
WINDOW_60M = 3600 # 60 minutes

# Labeling thresholds
LABELING_THRESHOLDS = {
    "bruteforce_username_attempts": 10,      # attempts in 10 minutes
    "bruteforce_ip_attempts": 50,            # attempts from IP in 10 minutes
    "credential_stuffing_distinct_ips": 5,   # distinct IPs for username in 1 hour
    "account_takeover_failed_before_success": 5,  # failed attempts before success
    "geolocation_change_minutes": 1,         # minutes between logins from different countries
    "session_reuse_minutes": 5,               # minutes window for session reuse detection
}

# Scan options
SCAN_OPTIONS = {
    "timeout": 5,
    "retry_count": 3,
    "pattern_duration_minutes": 2,  # Duration to run each pattern (demo mode)
    "production_pattern_duration_minutes": 5,  # Production duration
}

# Request settings
REQUEST_SETTINGS = {
    "timeout": 5,
    "allow_redirects": False,
    "verify": False,  # Set to True in production with proper certs
}

# User agent pool for variety
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

# Test credentials pool
VALID_USERS = [
    ("admin", "password"),
    ("user1", "pass123"),
    ("user2", "pass456"),
    ("testuser", "testpass"),
    ("demo", "demo123"),
]

INVALID_PASSWORDS = ["wrong", "incorrect", "badpass", "12345", "password1", "test", "invalid"]

# Generate timestamp for file naming
def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# Log file paths
def get_log_file():
    return os.path.join(LOGS_DIR, f"scan_run_{get_timestamp()}.log")

def get_raw_events_file():
    return os.path.join(DATA_DIR, f"raw_login_events_{get_timestamp()}.log")

