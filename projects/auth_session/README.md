<<<<<<< HEAD
## 🔍 Project Overview

**WebScanPro** is an automated security testing tool for web applications, to be developed primarily **in Python 3.x** and augmented with **Machine Learning (ML) / Deep Learning (DL)** techniques where appropriate. The tool will identify common vulnerabilities such as **SQL Injection**, **Cross-Site Scripting (XSS)**, **Broken Authentication**, **Insecure Direct Object References (IDOR)**, and more. ML/DL components will be used for tasks like anomaly detection, automated classification of server responses, and reducing false positives.

> **Mandatory tech stack:** Python (required) + ML/DL (scikit-learn, TensorFlow/PyTorch, or similar).

---

##  Project Outcomes (explicit ML/DL requirement)

- Build a Python-based automated web scanner that implements the listed modules.
- Integrate ML/DL models to assist detection and prioritization of vulnerabilities (for example, classifiers to detect SQLi/XSS-like responses, anomaly detection for unusual server replies, or NLP-based parsing of error messages).
- Provide model training scripts, dataset creation procedures, and evaluation metrics (precision, recall, F1-score).
- Deliver comprehensive reports combining rule-based detections and ML-driven insights.

---

##  Technologies Used

- **Programming language:** Python 3.x (required)
- **Web interaction & scraping:** Requests, BeautifulSoup, Selenium
- **Reporting & templating:** Jinja2, PDFKit / WeasyPrint
- **ML/DL (required integration):** scikit-learn (baseline models), TensorFlow or PyTorch (for deep models)
- **Data tooling:** pandas, numpy, joblib (model persistence)
- **Deployment/target platforms:** Docker
- **Target apps for testing:** DVWA
=======
# Authentication & Session Security Testing Module

This module collects and produces a cleaned, labeled dataset of login/session events for ML anomaly detection training.

## Quick Start

### 1. Generate Dataset

Run the authentication scanner to simulate login attempts and capture events:

```bash
# Set authentication endpoint (default: http://localhost:3000/login.php)
export AUTH_LOGIN_URL="http://your-test-env/login.php"

# Run scanner
python projects/auth_session/scanner/auth_scanner.py
```

This will generate:
- `data/raw_login_events_<timestamp>.log` - Raw event logs
- `data/login_session_dataset.csv` - Cleaned, labeled dataset
- `logs/scan_run_<timestamp>.log` - Scanner execution log

### 2. Extract ML Features

Extract ML-ready features from the dataset:

```bash
python projects/auth_session/ml/feature_extractor.py \
    --input data/login_session_dataset.csv \
    --output data/feature_dataset.csv
```

This generates `data/feature_dataset.csv` with extracted features ready for ML model training.

## Directory Structure

```
projects/auth_session/
├── docs/
│   ├── auth_patterns.md          # Attack pattern definitions
│   └── dataset_notes.md          # Labeling heuristics, privacy, validation
├── data/
│   ├── attack_patterns.csv       # Test scenario definitions
│   ├── login_session_dataset.csv # Raw event dataset
│   └── feature_dataset.csv       # ML-ready features
├── scanner/
│   └── auth_scanner.py           # Main scanner script
├── ml/
│   └── feature_extractor.py      # Feature extraction script
└── logs/                          # Execution logs
```

## Configuration

### Environment Variables

- `AUTH_LOGIN_URL`: Login endpoint URL (default: `http://localhost:3000/login.php`)
- `AUTH_LOGOUT_URL`: Logout endpoint URL (default: `http://localhost:3000/logout.php`)
- `AUTH_SESSION_REFRESH_URL`: Session refresh endpoint (default: `http://localhost:3000/session/refresh`)
- `AUTH_HASH_SALT`: Salt for anonymization (default: `auth_dataset_salt_2025`)

### Attack Patterns

Edit `data/attack_patterns.csv` to customize attack scenarios:

- `pattern_id`: Unique identifier
- `description`: Pattern description
- `attempt_rate`: Attempts per minute
- `distributed_flag`: 1 for distributed attacks (multiple IPs), 0 for single IP
- `notes`: Additional notes

## Usage Examples

### Basic Usage

```python
from projects.auth_session.scanner import AuthScanner

scanner = AuthScanner(base_url="http://localhost:3000/login.php")

# Simulate single login
event = scanner.simulate_login("user1", "password123", ip_address="192.168.1.100")
print(event)

# Save dataset
scanner.save_dataset()
```

### Feature Extraction

```python
from projects.auth_session.ml import FeatureExtractor

extractor = FeatureExtractor(
    input_file="data/login_session_dataset.csv",
    output_file="data/feature_dataset.csv"
)
extractor.run()
```

## Dataset Schema

### login_session_dataset.csv

| Column | Description |
|--------|-------------|
| `event_id` | Unique event identifier (UUID) |
| `timestamp` | ISO8601 timestamp |
| `username_anon` | Anonymized username (HMAC hash) |
| `ip_address_anon` | Anonymized IP address |
| `auth_result` | `success`, `failure`, `locked`, `rate_limited` |
| `is_bruteforce_candidate` | Binary label (0/1) |
| `is_anomalous` | Binary label for ML (0/1) |
| ... | See `docs/dataset_notes.md` for full schema |

### feature_dataset.csv

| Column | Description |
|--------|-------------|
| `fail_count_5m` | Failed attempts in 5-minute window |
| `fail_count_60m` | Failed attempts in 60-minute window |
| `distinct_ips_60m` | Distinct IPs per username |
| `velocity_score` | Composite attack velocity score |
| ... | See `docs/dataset_notes.md` for full feature list |

## Labeling

Automated labeling heuristics:

- **is_bruteforce_candidate = 1** if:
  - >= 10 attempts for username in 10 minutes, OR
  - >= 50 attempts from IP in 10 minutes, OR
  - > 5 distinct IPs for username in 1 hour

- **is_anomalous = 1** if:
  - Bruteforce candidate, OR
  - Rate-limited (429), OR
  - Success after >= 5 failures, OR
  - Session reused from different IP

See `docs/auth_patterns.md` and `docs/dataset_notes.md` for details.

## Privacy & Security

- All PII (usernames, IPs, session IDs) are anonymized using HMAC-SHA256
- No plaintext passwords or credentials stored
- Salt can be configured via `AUTH_HASH_SALT` environment variable
- See `docs/dataset_notes.md` for privacy compliance details

## Requirements

```bash
pip install requests
```

Optional for advanced features:
```bash
pip install pandas numpy  # For data analysis
```

## Next Steps

1. **Train ML Models**: Use `feature_dataset.csv` to train anomaly detection models
2. **Validate Dataset**: Run validation checks (see `docs/dataset_notes.md`)
3. **Adjust Patterns**: Modify `attack_patterns.csv` for different attack scenarios
4. **Integrate**: Use trained models in production authentication systems

## Documentation

- [Authentication Patterns](docs/auth_patterns.md) - Attack pattern definitions
- [Dataset Notes](docs/dataset_notes.md) - Labeling, privacy, validation

## License

See project root LICENSE file.

>>>>>>> 16866ac (Added auth_session project module)
