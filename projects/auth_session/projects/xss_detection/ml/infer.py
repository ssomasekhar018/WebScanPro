"""
Inference script for XSS detection model
"""
import os
import json
import pickle
import time
import torch
import numpy as np
import re

from models import LSTMClassifier, CNNClassifier
from utils import CharacterTokenizer, load_model

class XSSDetector:
    """XSS detection model for inference"""
    _instance = None
    
    @classmethod
    def get(cls):
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self, model_timestamp=None):
        """Initialize XSS detector"""
        # Load model, tokenizer and config
        model_dir = os.path.join('projects', 'xss_detection', 'models')
        
        if model_timestamp is None:
            # Find latest model
            model_files = [f for f in os.listdir(model_dir) if f.startswith('best_model_') and f.endswith('.pt')]
            if not model_files:
                raise FileNotFoundError("No model files found")
            
            # Sort by timestamp
            model_files.sort(reverse=True)
            model_timestamp = model_files[0].split('_')[1].split('.')[0]
        
        # Load config
        config_path = os.path.join(model_dir, f'best_model_{model_timestamp}_config.json')
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # Determine model class
        model_class = LSTMClassifier if self.config['model_type'] == 'lstm' else CNNClassifier
        
        # Load model
        self.model, self.tokenizer, _ = load_model(model_class, model_timestamp)
        
        # Load feature scaler
        scaler_path = os.path.join(model_dir, 'feature_scaler.pkl')
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Set model to evaluation mode
        self.model.eval()
        
        # Check for GPU
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = self.model.to(self.device)
        
        print(f"Loaded {self.config['model_type'].upper()} model from timestamp: {model_timestamp}")
    
    def extract_features(self, request_data, response_data):
        """Extract features from request and response data"""
        # Extract basic features
        features = {
            'html_content_length': response_data.get('content_length', 0),
            'reflected_payload_present': 1 if request_data.get('payload', '') in response_data.get('body', '') else 0,
            'status_group': int(str(response_data.get('status_code', 200))[0])
        }
        
        # Add regex-based flags
        payload = request_data.get('payload', '')
        features['has_script_tag'] = 1 if '<script>' in payload.lower() else 0
        features['has_onerror'] = 1 if 'onerror' in payload.lower() else 0
        features['has_javascript'] = 1 if 'javascript:' in payload.lower() else 0
        
        return features
    
    def predict(self, request_data, response_data):
        """Predict if a request/response pair contains an XSS attack"""
        start_time = time.time()
        
        # Clean payload
        payload = request_data.get('payload', '')
        if not isinstance(payload, str):
            payload = str(payload)
        
        # Normalize whitespace
        payload = re.sub(r'\s+', ' ', payload)
        
        # Extract features
        features = self.extract_features(request_data, response_data)
        
        # Tokenize payload
        encoded_inputs = self.tokenizer(
            [payload],
            padding='max_length',
            truncation=True,
            max_length=self.config['max_length'],
            return_tensors='pt'
        )
        
        # Prepare numerical features
        numerical_features = np.array([
            features['html_content_length'],
            features['reflected_payload_present'],
            features['status_group'],
            features['has_script_tag'],
            features['has_onerror'],
            features['has_javascript']
        ]).reshape(1, -1).astype(np.float32)
        
        # Scale numerical features
        numerical_features = self.scaler.transform(numerical_features)
        
        # Convert to tensors
        input_ids = encoded_inputs['input_ids'].to(self.device)
        attention_mask = encoded_inputs['attention_mask'].to(self.device)
        numerical_features = torch.tensor(numerical_features, dtype=torch.float32).to(self.device)
        
        # Make prediction
        with torch.no_grad():
            output = self.model(input_ids, attention_mask, numerical_features)
            probability = output.item()
            prediction = 1 if probability >= 0.5 else 0
        
        # Calculate inference time
        inference_time = (time.time() - start_time) * 1000  # ms
        
        return {
            'is_malicious': bool(prediction),
            'probability': probability,
            'inference_time_ms': inference_time
        }

if __name__ == "__main__":
    # Example usage
    detector = XSSDetector.get()
    
    # Test benign example
    benign_request = {
        'method': 'GET',
        'payload': 'hello'
    }
    
    benign_response = {
        'status_code': 200,
        'body': '<html><body>hello</body></html>',
        'content_length': 32
    }
    
    result = detector.predict(benign_request, benign_response)
    print(f"Benign example - is_malicious: {result['is_malicious']}, probability: {result['probability']:.4f}")
    
    # Test malicious example
    malicious_request = {
        'method': 'GET',
        'payload': '<script>alert(1)</script>'
    }
    
    malicious_response = {
        'status_code': 200,
        'body': '<html><body><script>alert(1)</script></body></html>',
        'content_length': 52
    }
    
    result = detector.predict(malicious_request, malicious_response)
    print(f"Malicious example - is_malicious: {result['is_malicious']}, probability: {result['probability']:.4f}")