"""
Configuration file for the unified vulnerability scanner.
Contains paths, thresholds, and scan options.
"""

import os
from datetime import datetime

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))

# Model paths
MODEL_PATHS = {
    "xss": os.path.join(PROJECT_ROOT, "projects", "xss_detection", "models", "best_model_20251029_132159.pt"),
    "sqli": os.path.join(PROJECT_ROOT, "projects", "sql_injection", "models", "best_model.pkl")
}

# Tokenizer/vectorizer paths
TOKENIZER_PATHS = {
    "xss": os.path.join(PROJECT_ROOT, "projects", "xss_detection", "models", "best_model_20251029_132159_tokenizer.json"),
    "sqli": os.path.join(PROJECT_ROOT, "projects", "sql_injection", "models", "preprocessor.pkl")
}

# Classification thresholds
THRESHOLDS = {
    "xss": 0.75,
    "sqli": 0.70
}

# Scan options
SCAN_OPTIONS = {
    "timeout": 5,
    "max_payloads": 50,
    "threads": 4,
    "retry_count": 3
}

# Output paths
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
REPORT_DIR = os.path.join(OUTPUT_DIR, "scan_reports")
LOG_DIR = os.path.join(OUTPUT_DIR, "logs")

# Ensure directories exist
for directory in [OUTPUT_DIR, REPORT_DIR, LOG_DIR]:
    os.makedirs(directory, exist_ok=True)

# Generate timestamp for file naming
def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# Default report filename
def get_report_filename():
    return os.path.join(REPORT_DIR, f"report_{get_timestamp()}.json")

# Logging configuration
LOG_CONFIG = {
    "filename": os.path.join(LOG_DIR, f"scan_run_{get_timestamp()}.log"),
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
}
