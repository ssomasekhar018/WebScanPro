# XSS Response Dataset Notes

## Labeling Heuristics
- `is_malicious=1`: If `reflected_payload_present=1` (exact match in body) OR suspicious tags like 'alert(' or 'onerror' in response.
- `is_malicious=0`: No reflection, server errors (5xx), or sanitized output.
- `script_executed_flag`: Manual (1 if alert would pop in browser; test top 20%).
- Ambiguous: Flagged in `notes`; e.g., encoded payloads needing decode check.

## Dataset Collection Process
- **Target Application**: DVWA (Damn Vulnerable Web Application) running on localhost:3000
- **Collection Method**: Automated scanner with two phases:
  1. Reflected XSS: Injecting payloads via URL parameters
  2. Stored XSS: Two-step process - insert payload, then visit page to capture response
- **Response Capture**: Full HTTP response including headers, body, and timing metrics
- **Snapshot Storage**: HTML snapshots saved for manual verification in logs/snapshots/

## Automatic Labeling Logic
- **Primary Indicators**: 
  - Direct payload reflection in response body
  - Presence of script tags or event handlers in response
  - Known XSS patterns in unescaped form
- **Secondary Indicators**:
  - Error messages that indicate successful injection
  - HTML structure disruption patterns

## Manual Verification Process
- 20% of samples manually verified to ensure labeling accuracy
- Focus on edge cases and obfuscated payloads
- Browser-based verification for script execution confirmation

## Stats
- Total rows: 8 (4 reflected + 4 stored)
- Malicious samples: 4 (50%)
- Benign samples: 4 (50%)
- Manual verification rate: 100% of dataset

## Dataset Limitations
- Limited payload variety - expanded dataset would benefit from more obfuscation techniques
- No DOM-based XSS examples included
- Test environment is controlled - real-world responses may vary
- Script execution flags require browser verification

## Future Improvements
- Expand payload variety with more obfuscation techniques
- Include DOM-based XSS examples
- Implement automated browser-based verification for script execution
- Add more context-specific payloads (e.g., JSON, XML contexts)
- Sources: OWASP/PortSwigger payloads injected into Juice Shop v15.0.0

## Issues
- Stored: Limited persistence in Juice Shop; used simulated 2-step (POST + GET).
- Size: ~2MB; truncated bodies for privacy.

Generated: Oct 24, 2025