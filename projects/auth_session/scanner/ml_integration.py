import joblib
import logging
import pandas as pd
from projects.sql_injection.scripts.feature_engineering import extract_features

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
            if preprocessor_path:
                self.preprocessor = joblib.load(preprocessor_path)
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            self.model = None
            self.preprocessor = None

    def prepare_features(self, request, response):
        features_dict = extract_features(request, response)
        features_df = pd.DataFrame([features_dict])
        if self.preprocessor:
            features_df = self.preprocessor.transform(features_df)
        return features_df

    def predict(self, features):
        if self.model is None:
            return "unknown", 0.0
        try:
            label = self.model.predict(features)[0]
            confidence = max(self.model.predict_proba(features)[0]) if hasattr(self.model, 'predict_proba') else 1.0
            logger.info(f"Prediction: {label}, Confidence: {confidence}")
            return label, confidence
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return "unknown", 0.0