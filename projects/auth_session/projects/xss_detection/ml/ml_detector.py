# projects/xss_detection/ml/ml_detector.py
from projects.xss_detection.scanner.integrate_with_scanner import XSSDetector

detect = XSSDetector.get().predict

# Example usage:
# result = detect({"method":"GET","payload":"<script>alert(1)</script>"}, response_obj)