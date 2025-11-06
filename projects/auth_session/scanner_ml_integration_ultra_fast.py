#!/usr/bin/env python3
"""
Ultra-fast ML Integration Server for Authentication Scanner
Uses pre-computed feature vectors for minimal latency
"""

import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
import numpy as np
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

print("Starting ultra-fast ML integration server...")

# Define paths
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'ml')
IFOREST_MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest_model.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')

# Global model variables
scaler = None
iforest = None

# Pre-computed column mappings and feature vectors
FEATURE_VECTOR_SIZE = 308
SCALER_MEANS = None
SCALER_SCALES = None

# Fast feature extraction mapping
FEATURE_MAPPING = {
    'login_rate': 0,
    'session_duration': 1,
    'failed_login_rate': 2,
    'device_change_rate': 3,
    'location_change_rate': 4,
    'time_since_last_login': 5,
    'avg_login_interval': 6,
    'failed_login_ratio': 7,
    'device_diversity': 8,
    'location_diversity': 9,
    'hour_of_day': 10,
    'day_of_week': 11,
    'is_weekend': 12,
    'is_business_hours': 13,
    'is_night_hours': 14,
    'login_count_24h': 15,
    'failed_count_24h': 16,
    'device_count_24h': 17,
    'location_count_24h': 18,
    'max_login_rate_24h': 19
}

def init_models():
    """Initialize and cache models with pre-computed values"""
    global scaler, iforest, SCALER_MEANS, SCALER_SCALES
    
    logger.info("Initializing ultra-fast ML models...")
    start_time = time.time()
    
    try:
        # Load models
        logger.info("Loading scaler...")
        scaler = joblib.load(SCALER_PATH)
        logger.info("Loading isolation forest...")
        iforest = joblib.load(IFOREST_MODEL_PATH)
        
        # Pre-compute scaler parameters for faster scaling
        SCALER_MEANS = scaler.mean_
        SCALER_SCALES = scaler.scale_
        
        init_time = time.time() - start_time
        logger.info(f"Ultra-fast models initialized in {init_time:.2f}s")
        logger.info(f"Feature vector size: {FEATURE_VECTOR_SIZE}")
        
    except Exception as e:
        logger.error(f"Error initializing models: {str(e)}")
        raise

def ultra_fast_preprocess(data):
    """Ultra-fast preprocessing using direct feature mapping"""
    # Create feature vector directly
    features = np.zeros(FEATURE_VECTOR_SIZE)
    
    # Fill numerical features directly
    for feature_name, idx in FEATURE_MAPPING.items():
        if feature_name in data:
            features[idx] = float(data[feature_name])
    
    # Apply scaling (pre-computed for speed)
    features[:len(SCALER_MEANS)] = (features[:len(SCALER_MEANS)] - SCALER_MEANS) / SCALER_SCALES
    
    return features.reshape(1, -1)

def ultra_fast_predict(features):
    """Ultra-fast prediction using only Isolation Forest"""
    # Isolation Forest prediction
    iforest_score = iforest.decision_function(features)
    
    # Fast anomaly detection (simplified threshold)
    is_anomalous = abs(iforest_score[0]) > 0.2
    
    return {
        'iforest_score': float(iforest_score[0]),
        'is_anomalous': bool(is_anomalous),
        'confidence': min(abs(iforest_score[0]) * 1.5, 1.0)
    }

# Initialize Flask app
app = Flask(__name__)
logger.info("Ultra-fast Flask app created")

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'models_loaded': scaler is not None and iforest is not None,
        'timestamp': time.time()
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Ultra-fast prediction endpoint"""
    start_time = time.time()
    
    try:
        # Parse request data
        data = request.get_json(force=True)
        session_id = data.get('session_id', 'unknown')
        
        # Ultra-fast preprocessing
        features = ultra_fast_preprocess(data)
        
        # Ultra-fast prediction
        result = ultra_fast_predict(features)
        
        # Build response
        response = {
            'session_id': session_id,
            'iforest_score': result['iforest_score'],
            'final_label': 'anomalous' if result['is_anomalous'] else 'normal',
            'confidence': result['confidence']
        }
        
        processing_time = (time.time() - start_time) * 1000
        response['processing_time_ms'] = processing_time
        
        logger.info(f"Ultra-fast prediction: {processing_time:.2f}ms")
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting ultra-fast model initialization...")
    init_models()
    logger.info("Starting Ultra-fast Flask ML Integration Server on port 5001")
    app.run(port=5001, debug=False, threaded=True)