# Integration Report - Oct 22, 2025

## Test Results
- Unit tests: 4/4 passed.
- Integration: Scanned sample_requests.json; 1 malicious detected with 0.9 conf, 1 safe with 0.95 conf.
- Latency: ~20ms/req on local machine.

## Open Issues
- Potential false positives on edge cases; monitor logs.
- No high-throughput testing yet.

## Checklist
- [x] Code integrated
- [x] CLI flag added
- [x] Tests pass
- [x] Docs updated
- [x] Verified end-to-end