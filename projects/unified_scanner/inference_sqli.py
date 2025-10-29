"""
SQLi inference module for the unified vulnerability scanner.
Loads SQLi model and provides prediction functionality.
"""

import os
import sys
import logging
import joblib
import pandas as pd
import time

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from projects.sql_injection.scripts.feature_engineering import extract_features

logger = logging.getLogger(__name__)

class SQLiDetector:
    def __init__(self, model_path, vectorizer_path):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.model = None
        self.vectorizer = None
        self.load_model()
    
    def load_model(self):
        """Load the trained SQLi model and vectorizer."""
        try:
            logger.info(f"Loading SQLi model from {self.model_path}")
            self.model = joblib.load(self.model_path)
            
            if self.vectorizer_path:
                logger.info(f"Loading SQLi vectorizer from {self.vectorizer_path}")
                self.vectorizer = joblib.load(self.vectorizer_path)
                
            logger.info("SQLi model and vectorizer loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to load SQLi model: {str(e)}")
            return False
    
    def prepare_features(self, request, response):
        """Extract and prepare features for SQLi detection."""
        try:
            features_dict = extract_features(request, response)
            features_df = pd.DataFrame([features_dict])
            
            if self.vectorizer:
                features_df = self.vectorizer.transform(features_df)
                
            return features_df
        except Exception as e:
            logger.error(f"Error preparing SQLi features: {str(e)}")
            return None
    
    def predict_sqli(self, request, response):
        """
        Predict if a request-response pair contains SQL injection.
        
        Args:
            request: HTTP request object or dictionary
            response: HTTP response object or dictionary
            
        Returns:
            dict: Prediction result with probability and label
        """
        if self.model is None:
            logger.error("SQLi model not loaded")
            return {"prob": 0.0, "label": "unknown", "error": "Model not loaded"}
        
        try:
            start_time = time.time()
            
            # Prepare features
            features = self.prepare_features(request, response)
            if features is None:
                return {"prob": 0.0, "label": "unknown", "error": "Feature extraction failed"}
            
            # Make prediction
            prediction = self.model.predict(features)[0]
            
            # Get probability
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(features)[0]
                prob = probabilities[1] if prediction == 1 else probabilities[0]
            else:
                prob = 1.0 if prediction == 1 else 0.0
            
            # Convert numeric label to string
            label = "malicious" if prediction == 1 else "benign"
            
            inference_time = time.time() - start_time
            logger.info(f"SQLi prediction: {label} (prob: {prob:.4f}, time: {inference_time:.4f}s)")
            
            return {
                "prob": float(prob),
                "label": label,
                "inference_time": inference_time
            }
            
        except Exception as e:
            logger.error(f"SQLi prediction error: {str(e)}")
            return {"prob": 0.0, "label": "error", "error": str(e)}


# Singleton instance
_instance = None

def get_sqli_detector(model_path, vectorizer_path):
    """Get or create SQLi detector singleton instance."""
    global _instance
    if _instance is None:
        _instance = SQLiDetector(model_path, vectorizer_path)
    return _instance