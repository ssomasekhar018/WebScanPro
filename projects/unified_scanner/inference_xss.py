"""
XSS inference module for the unified vulnerability scanner.
Loads XSS model and provides prediction functionality.
"""

import os
import sys
import logging
import json
import time
import torch
import torch.nn as nn
import torch.nn.functional as F

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

logger = logging.getLogger(__name__)

class XSSDetector:
    def __init__(self, model_path, tokenizer_path):
        self.model_path = model_path
        self.tokenizer_path = tokenizer_path
        self.model = None
        self.tokenizer = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.load_model()
    
    def load_model(self):
        """Load the trained XSS model and tokenizer."""
        try:
            logger.info(f"Loading XSS model from {self.model_path}")
            self.model = torch.load(self.model_path, map_location=self.device)
            self.model.eval()  # Set to evaluation mode
            
            logger.info(f"Loading XSS tokenizer from {self.tokenizer_path}")
            with open(self.tokenizer_path, 'r') as f:
                self.tokenizer = json.load(f)
                
            logger.info(f"XSS model loaded successfully (using {self.device})")
            return True
        except Exception as e:
            logger.error(f"Failed to load XSS model: {str(e)}")
            return False
    
    def preprocess_text(self, text):
        """Preprocess and tokenize text for XSS detection."""
        try:
            # Basic preprocessing (implement according to your training pipeline)
            text = str(text).lower()
            
            # Tokenization (simplified - adapt to your actual tokenizer)
            if hasattr(self.tokenizer, 'encode'):
                # If using a Hugging Face tokenizer
                tokens = self.tokenizer.encode(text, truncation=True, max_length=512)
                return torch.tensor([tokens], device=self.device)
            else:
                # If using a custom tokenizer
                # This is a simplified example - adapt to your actual tokenization logic
                tokens = []
                for char in text:
                    token_id = self.tokenizer.get(char, self.tokenizer.get('UNK', 0))
                    tokens.append(token_id)
                
                # Truncate or pad as needed
                max_len = 512
                if len(tokens) > max_len:
                    tokens = tokens[:max_len]
                else:
                    tokens = tokens + [0] * (max_len - len(tokens))
                
                return torch.tensor([tokens], device=self.device)
        except Exception as e:
            logger.error(f"Error preprocessing text: {str(e)}")
            return None
    
    def predict_xss(self, response_text):
        """
        Predict if a response contains XSS vulnerabilities.
        
        Args:
            response_text: HTTP response text or HTML content
            
        Returns:
            dict: Prediction result with probability and label
        """
        if self.model is None:
            logger.error("XSS model not loaded")
            return {"prob": 0.0, "label": "unknown", "error": "Model not loaded"}
        
        try:
            start_time = time.time()
            
            # Preprocess input
            inputs = self.preprocess_text(response_text)
            if inputs is None:
                return {"prob": 0.0, "label": "unknown", "error": "Preprocessing failed"}
            
            # Make prediction
            with torch.no_grad():
                outputs = self.model(inputs)
                
                # Get probabilities
                if isinstance(outputs, tuple):
                    outputs = outputs[0]  # Some models return (logits, hidden_states)
                
                if isinstance(outputs, torch.Tensor):
                    if outputs.dim() > 1 and outputs.size(1) > 1:
                        # Multi-class classification
                        probs = F.softmax(outputs, dim=1)
                        predicted_class = torch.argmax(probs, dim=1).item()
                        prob = probs[0][predicted_class].item()
                        label = "malicious" if predicted_class == 1 else "benign"
                    else:
                        # Binary classification
                        prob = torch.sigmoid(outputs).item()
                        label = "malicious" if prob >= 0.5 else "benign"
                else:
                    # Handle other output types
                    prob = float(outputs)
                    label = "malicious" if prob >= 0.5 else "benign"
            
            inference_time = time.time() - start_time
            logger.info(f"XSS prediction: {label} (prob: {prob:.4f}, time: {inference_time:.4f}s)")
            
            return {
                "prob": float(prob),
                "label": label,
                "inference_time": inference_time
            }
            
        except Exception as e:
            logger.error(f"XSS prediction error: {str(e)}")
            return {"prob": 0.0, "label": "error", "error": str(e)}


# Singleton instance
_instance = None

def get_xss_detector(model_path, tokenizer_path):
    """Get or create XSS detector singleton instance."""
    global _instance
    if _instance is None:
        _instance = XSSDetector(model_path, tokenizer_path)
    return _instance