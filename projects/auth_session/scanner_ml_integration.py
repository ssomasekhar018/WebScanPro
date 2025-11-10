
import pandas as pd
import numpy as np
import joblib
import os
import datetime

# Generate a timestamp for the log file
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"projects/auth_session/logs/scanner_inference_{timestamp}.log"

def log_message(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

# Load the IDOR model and preprocessor
log_message("Loading IDOR model...")
pipeline = joblib.load("projects/auth_session/ml/idor_model.joblib")
log_message("IDOR model loaded successfully.")

def score_session(session_data):
    """
    Scores a session for IDOR anomalies using the trained model.

    Args:
        session_data (dict): A dictionary of session features.

    Returns:
        dict: A dictionary with the anomaly score and final label.
    """
    df = pd.DataFrame([session_data])
    
    df_for_prediction = df.drop(columns=["is_unauthorized"], errors="ignore")

    # The pipeline handles both preprocessing and prediction
    prediction = pipeline.predict(df_for_prediction)[0]
    probability = pipeline.predict_proba(df_for_prediction)[0][1] # Probability of being anomalous

    final_label = "anomalous" if prediction == 1 else "normal"

    result = {
        "session_id": session_data.get("request_id", "N/A"),
        "idor_probability": probability,
        "final_label": final_label
    }
    
    log_message(f"Scoring result: {result}")
    return result

