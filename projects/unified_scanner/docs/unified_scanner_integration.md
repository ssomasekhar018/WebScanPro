# Unified Scanner Integration Documentation

## Architecture Overview

The Unified Vulnerability Scanner integrates both XSS and SQL Injection detection capabilities into a single scanning pipeline. It leverages trained ML/DL models to detect vulnerabilities in web applications by analyzing HTTP responses.

### Key Components

1. **Unified Scanner Orchestrator** (`unified_scanner.py`)
   - Main entry point for scanning operations
   - Coordinates the scanning process across multiple URLs
   - Manages parallel execution of scans

2. **Inference Modules**
   - `inference_xss.py`: Loads XSS detection model and provides prediction functionality
   - `inference_sqli.py`: Loads SQLi detection model and provides prediction functionality

3. **Configuration Management** (`config.py`)
   - Centralizes paths, thresholds, and scan options
   - Enables easy switching between model versions

4. **Reporting System** (`reporting.py`)
   - Aggregates scan results
   - Generates JSON and CSV reports
   - Provides console summary output

5. **Utilities** (`utils.py`)
   - HTTP request handling
   - Payload generation
   - Logging configuration

## Component Interactions

```
                  ┌─────────────────┐
                  │  unified_scanner│
                  │  (Orchestrator) │
                  └────────┬────────┘
                           │
           ┌───────────────┴───────────────┐
           │                               │
  ┌────────▼─────────┐           ┌────────▼─────────┐
  │  inference_xss   │           │  inference_sqli  │
  │  (XSS Detector)  │           │  (SQLi Detector) │
  └────────┬─────────┘           └────────┬─────────┘
           │                               │
           └───────────────┬───────────────┘
                           │
                  ┌────────▼────────┐
                  │    reporting    │
                  │ (Result Output) │
                  └─────────────────┘
```

## Usage Examples

### Basic Usage

Scan a single URL:
```bash
python unified_scanner.py --url https://testsite.com/login --output report.json
```

Scan multiple URLs from a file:
```bash
python unified_scanner.py --url-list urls.txt --output report.json
```

### Advanced Options

Customize scan parameters:
```bash
python unified_scanner.py --url-list urls.txt --threads 8 --timeout 10 --max-payloads 100
```

Adjust detection thresholds:
```bash
python unified_scanner.py --url-list urls.txt --xss-threshold 0.8 --sqli-threshold 0.7
```

Use specific model versions:
```bash
python unified_scanner.py --url-list urls.txt --xss-model ../xss_detection/models/best_model_20251026.pt --sqli-model ../sql_injection/models/best_model_20251023.pkl
```

## Output Format

The scanner produces a JSON report with the following structure:

```json
{
  "summary": {
    "total_urls": 2,
    "xss_detected": 1,
    "sqli_detected": 1,
    "high_risk_urls": 1,
    "medium_risk_urls": 1,
    "low_risk_urls": 0,
    "timestamp": "2025-10-28T15:30:45.123456"
  },
  "results": [
    {
      "url": "https://testsite.com/login",
      "timestamp": "2025-10-28T15:30:40.123456",
      "xss": {
        "is_vulnerable": true,
        "probability": 0.92,
        "payloads_tested": 20,
        "vulnerable_payloads": [
          {
            "payload": "<script>alert('XSS')</script>",
            "probability": 0.92
          }
        ]
      },
      "sqli": {
        "is_vulnerable": false,
        "probability": 0.18,
        "payloads_tested": 20,
        "vulnerable_payloads": []
      }
    },
    {
      "url": "https://testsite.com/search",
      "timestamp": "2025-10-28T15:30:42.123456",
      "xss": {
        "is_vulnerable": false,
        "probability": 0.35,
        "payloads_tested": 20,
        "vulnerable_payloads": []
      },
      "sqli": {
        "is_vulnerable": true,
        "probability": 0.83,
        "payloads_tested": 20,
        "vulnerable_payloads": [
          {
            "payload": "' OR '1'='1",
            "probability": 0.83
          }
        ]
      }
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **Model Loading Failures**
   - Ensure model paths in `config.py` are correct
   - Verify model file formats match the expected types (PyTorch .pt for XSS, joblib .pkl for SQLi)

2. **HTTP Request Errors**
   - Check network connectivity
   - Increase timeout value with `--timeout` parameter
   - Verify target URLs are accessible

3. **Performance Issues**
   - Adjust thread count with `--threads` parameter
   - Reduce number of payloads with `--max-payloads` parameter
   - Use smaller models if available

### Known Limitations

1. **False Positives/Negatives**
   - Detection accuracy depends on model quality
   - Adjust thresholds to balance between false positives and false negatives

2. **Resource Usage**
   - Deep learning models (especially XSS) may require significant memory
   - Consider using GPU acceleration if available

3. **Scan Duration**
   - Full scans with many payloads can take time
   - Use threading and payload limits to manage scan duration