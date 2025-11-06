#!/usr/bin/env python3
"""
Optimized ML Integration Server for Authentication Scanner
Focuses on low-latency predictions for real-time authentication
"""

import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
import numpy as np
import logging
import time
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

print("Starting optimized ML integration server...")

# Define paths
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'ml')
DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'feature_dataset.csv')
IFOREST_MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest_model.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')

logger.info(f"MODEL_DIR: {MODEL_DIR}")
logger.info(f"DATA_PATH: {DATA_PATH}")
logger.info(f"IFOREST_MODEL_PATH: {IFOREST_MODEL_PATH}")
logger.info(f"SCALER_PATH: {SCALER_PATH}")

# Global model variables
scaler = None
iforest = None

# Cache for column information
TRAINING_COLUMNS = None
NUMERICAL_COLS = None
CATEGORICAL_COLS = None

def init_models():
    """Initialize and cache models"""
    global scaler, iforest, TRAINING_COLUMNS, NUMERICAL_COLS, CATEGORICAL_COLS
    
    logger.info("Initializing ML models...")
    start_time = time.time()
    
    try:
        # Load models
        logger.info("Loading scaler...")
        scaler = joblib.load(SCALER_PATH)
        logger.info("Loading isolation forest...")
        iforest = joblib.load(IFOREST_MODEL_PATH)
        
        # Load training data to get column info
        logger.info("Loading training data...")
        training_df = pd.read_csv(DATA_PATH)
        X_train = training_df.drop("is_anomalous", axis=1)
        
        NUMERICAL_COLS = X_train.select_dtypes(include=np.number).columns.tolist()
        CATEGORICAL_COLS = X_train.select_dtypes(exclude=np.number).columns.tolist()
        
        # Pre-compute training columns for alignment
        X_train_encoded = pd.get_dummies(X_train, columns=CATEGORICAL_COLS, drop_first=True)
        TRAINING_COLUMNS = X_train_encoded.columns.tolist()
        
        init_time = time.time() - start_time
        logger.info(f"Models initialized successfully in {init_time:.2f}s")
        logger.info(f"Numerical columns: {len(NUMERICAL_COLS)}")
        logger.info(f"Categorical columns: {len(CATEGORICAL_COLS)}")
        logger.info(f"Total training columns: {len(TRAINING_COLUMNS)}")
        
    except Exception as e:
        logger.error(f"Error initializing models: {str(e)}")
        raise

def fast_preprocess(data):
    """Fast preprocessing optimized for single predictions"""
    # Create DataFrame
    df = pd.DataFrame(data, index=[0])
    
    # Fast one-hot encoding
    df_encoded = pd.get_dummies(df, columns=CATEGORICAL_COLS, drop_first=True)
    
    # Fast column alignment
    missing_cols = set(TRAINING_COLUMNS) - set(df_encoded.columns)
    for col in missing_cols:
        df_encoded[col] = 0
    
    # Remove extra columns and reorder
    df_aligned = df_encoded[TRAINING_COLUMNS]
    
    # Fast scaling for numerical columns
    df_aligned[NUMERICAL_COLS] = scaler.transform(df_aligned[NUMERICAL_COLS])
    
    return df_aligned

def predict_anomaly(features):
    """Fast anomaly prediction using only Isolation Forest (removing Autoencoder for speed)"""
    # Isolation Forest prediction
    iforest_score = iforest.decision_function(features)
    iforest_pred = iforest.predict(features)
    
    # Simple threshold-based anomaly detection (faster than autoencoder)
    # Use a more lenient threshold for faster classification
    is_anomalous = iforest_pred[0] == -1 or abs(iforest_score[0]) > 0.15
    
    return {
        'iforest_score': float(iforest_score[0]),
        'is_anomalous': bool(is_anomalous),
        'confidence': min(abs(iforest_score[0]) * 2, 1.0)  # Simple confidence score
    }

# Initialize Flask app
app = Flask(__name__)
logger.info("Flask app created")

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
    """Optimized prediction endpoint"""
    start_time = time.time()
    
    try:
        # Parse request data
        data = request.get_json(force=True)
        session_id = data.get('session_id', 'unknown')
        logger.info(f"Prediction request for session: {session_id}")
        
        # Fast preprocessing
        features = fast_preprocess(data)
        
        # Fast prediction
        result = predict_anomaly(features)
        
        # Build response
        response = {
            'session_id': session_id,
            'iforest_score': result['iforest_score'],
            'final_label': 'anomalous' if result['is_anomalous'] else 'normal',
            'confidence': result['confidence']
        }
        
        processing_time = (time.time() - start_time) * 1000
        response['processing_time_ms'] = processing_time
        
        logger.info(f"Prediction completed in {processing_time:.2f}ms")
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting model initialization...")
    init_models()
    logger.info("Starting Optimized Flask ML Integration Server on port 5000")
    app.run(port=5000, debug=False, threaded=True)