
import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
import numpy as np
import tensorflow as tf
import logging
import time

# Configure TensorFlow for better performance
tf.config.optimizer.set_jit(True)
tf.config.optimizer.set_experimental_options({"auto_mixed_precision": True})

# Define paths
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'ml')
DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'feature_dataset.csv')
IFOREST_MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest_model.pkl')
AUTOENCODER_MODEL_PATH = os.path.join(MODEL_DIR, 'autoencoder_model_fixed.h5')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')

# Global model variables
scaler = None
iforest = None
autoencoder = None

# Load training data and column info
X_train_encoded = None
TRAINING_COLUMNS = None
NUMERICAL_COLS = None
CATEGORICAL_COLS = None

def init_models():
    """Initialize and cache models"""
    global scaler, iforest, autoencoder, X_train_encoded, TRAINING_COLUMNS, NUMERICAL_COLS, CATEGORICAL_COLS
    
    logging.info("Initializing ML models...")
    start_time = time.time()
    
    # Load models
    scaler = joblib.load(SCALER_PATH)
    iforest = joblib.load(IFOREST_MODEL_PATH)
    autoencoder = load_model(AUTOENCODER_MODEL_PATH, compile=False)
    autoencoder.compile(optimizer='adam', loss='mae')
    
    # Load training data to get column info
    training_df = pd.read_csv(DATA_PATH)
    X_train = training_df.drop("is_anomalous", axis=1)
    
    NUMERICAL_COLS = X_train.select_dtypes(include=np.number).columns.tolist()
    CATEGORICAL_COLS = X_train.select_dtypes(exclude=np.number).columns.tolist()
    X_train_encoded = pd.get_dummies(X_train, columns=CATEGORICAL_COLS, drop_first=True)
    TRAINING_COLUMNS = X_train_encoded.columns.tolist()
    
    init_time = time.time() - start_time
    logging.info(f"Models initialized in {init_time:.2f}s")

def init_app(app):
    """Initialize Flask app with models"""
    init_models()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
logger.info("Flask app created")

@app.route('/login', methods=['POST'])
def login():
    return jsonify({'status': 'success'}), 200

@app.route('/predict', methods=['POST'])
def predict():
    start_time = time.time()
    
    try:
        data = request.get_json(force=True)
        logger.info(f"Received prediction request for session: {data.get('session_id', 'unknown')}")
        
        # Prepare data
        df = pd.DataFrame(data, index=[0])
        
        # One-hot encode categorical features
        df_encoded = pd.get_dummies(df, columns=CATEGORICAL_COLS, drop_first=True)
        
        # Align columns with the training data
        df_aligned = df_encoded.reindex(columns=TRAINING_COLUMNS, fill_value=0)
        
        # Scale numerical data
        df_aligned[NUMERICAL_COLS] = scaler.transform(df_aligned[NUMERICAL_COLS])
        
        # Get predictions from both models
        iforest_score = iforest.decision_function(df_aligned)
        iforest_pred = iforest.predict(df_aligned)
        
        # Autoencoder prediction (optimized)
        autoencoder_pred = autoencoder.predict(df_aligned, verbose=0)
        reconstruction_error = np.mean(np.power(df_aligned.values - autoencoder_pred, 2), axis=1)
        
        # Combine results
        final_label = "anomalous" if iforest_pred[0] == -1 or reconstruction_error[0] > 0.1 else "normal"
        
        response = {
            'session_id': data['session_id'],
            'iforest_score': float(iforest_score[0]),
            'autoencoder_error': float(reconstruction_error[0]),
            'final_label': final_label
        }
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"Prediction completed in {processing_time:.2f}ms")
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_app(app)
    # Run in production mode for better performance
    logger.info("Starting Flask ML Integration Server on port 5000")
    app.run(port=5000, debug=False, threaded=True)
