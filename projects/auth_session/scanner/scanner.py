# In scanner/scanner.py
from scanner.ml_integration import MLIntegrator
import logging

logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self, input_file):
        self.input_file = input_file
        # ... existing init ...

    def run(self, use_ml=False):
        results = []
        ml = None
        if use_ml:
            ml = MLIntegrator.get_instance()
            if ml.model is None:
                logger.error("ML fallback to rules-only")
        # Assume get_requests_responses() yields req-resp pairs
        for req, resp in self.get_requests_responses():
            result = {'request': req, 'response': resp}
            if use_ml and ml:
                features = ml.prepare_features(req, resp)
                label, conf = ml.predict(features)
                result['ml_label'] = label  # e.g., 0=safe, 1=malicious
                result['ml_confidence'] = conf
            results.append(result)
        return results

    def get_requests_responses(self):
        # Existing logic to load/parse input (e.g., from JSON or PCAP)
        pass