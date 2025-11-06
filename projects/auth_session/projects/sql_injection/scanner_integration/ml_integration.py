import pandas as pd
import joblib
import logging
import numpy as np
from projects.sql_injection.scripts.feature_engineering import extract_features  # Assuming this function exists in feature_engineering.py

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MLIntegrator:
    _instance = None
    model = None
    preprocessor = None

    @classmethod
    def get_instance(cls, model_path='projects/sql_injection/models/best_model.pkl', preprocessor_path='projects/sql_injection/models/preprocessor.pkl'):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load_model(model_path, preprocessor_path)
        return cls._instance

    def load_model(self, model_path, preprocessor_path):
        try:
            self.model = joblib.load(model_path)
            self.preprocessor = joblib.load(preprocessor_path) if preprocessor_path else None
            logger.info(f"Model loaded successfully from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            self.model = None
            self.preprocessor = None

    def prepare_features(self, request, response):
        # Wrapper to call feature extraction
        features = extract_features(request, response)  # Assuming extract_features returns a dict or list
        features_df = pd.DataFrame([features])  # Convert to DataFrame if needed
        if self.preprocessor:
            features_df = self.preprocessor.transform(features_df)
        return features_df

    def predict(self, features):
        if self.model is None:
            logger.error("Model not loaded. Cannot predict.")
            return "unknown", 0.0

        try:
            label = self.model.predict(features)[0]
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features)[0]
                confidence = max(proba)  # Assuming binary classification, take max probability
                logger.info(f"Prediction: {label}, Confidence: {confidence}")
            else:
                confidence = 1.0  # For models without proba, assume full confidence
                logger.info(f"Prediction: {label}, Confidence: {confidence}")
            return label, confidence
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return "unknown", 0.0