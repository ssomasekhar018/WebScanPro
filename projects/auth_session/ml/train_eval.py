
import os
import pandas as pd
import numpy as np
import joblib
import logging
import tensorflow as tf
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
)
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping

# Define paths
# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))
# Go up one level to the 'projects/auth_session' directory
project_dir = os.path.abspath(os.path.join(script_dir, '..'))

DATA_PATH = os.path.join(project_dir, "data", "feature_dataset.csv")
MODEL_DIR = os.path.join(project_dir, "ml")
DOCS_DIR = os.path.join(project_dir, "docs")
LOGS_DIR = os.path.join(project_dir, "logs")

# Configure logging
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
os.makedirs(LOGS_DIR, exist_ok=True)
log_file = os.path.join(LOGS_DIR, f"model_train_eval_{timestamp}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
)
# Create directories if they don't exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)

def load_and_prepare_data():
    """Loads the dataset, preprocesses it, and splits it into train, validation, and test sets."""
    logging.info("Loading and preparing data...")
    df = pd.read_csv(DATA_PATH)
    
    # Separate features and labels
    X = df.drop("is_anomalous", axis=1)
    y = df["is_anomalous"]
    
    # Identify categorical and numerical features
    categorical_cols = X.select_dtypes(include=['object', 'category']).columns
    numerical_cols = X.select_dtypes(include=np.number).columns
    
    # One-hot encode categorical features
    X = pd.get_dummies(X, columns=categorical_cols, drop_first=True)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_test, y_test, test_size=0.5, random_state=42, stratify=y_test
    )
    
    # Normalize numerical features
    scaler = StandardScaler()
    X_train[numerical_cols] = scaler.fit_transform(X_train[numerical_cols])
    X_val[numerical_cols] = scaler.transform(X_val[numerical_cols])
    X_test[numerical_cols] = scaler.transform(X_test[numerical_cols])
    
    # Save the scaler
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    
    logging.info("Data preparation complete.")
    return X_train, X_val, X_test, y_train, y_val, y_test

def train_isolation_forest(X_train, X_test, y_test):
    """Trains and evaluates the Isolation Forest model."""
    logging.info("Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100, contamination="auto", max_samples="auto", random_state=42
    )
    model.fit(X_train[y_train == 0])  # Train on normal data only
    
    # Predict on test data
    y_pred_scores = model.decision_function(X_test)
    y_pred = [1 if s < 0 else 0 for s in y_pred_scores]
    
    # Evaluate
    report = evaluate_model(y_test, y_pred, "Isolation Forest")
    
    # Save model
    joblib.dump(model, os.path.join(MODEL_DIR, "isolation_forest_model.pkl"))
    logging.info("Isolation Forest model saved.")
    
    return report

def train_autoencoder(X_train, X_val, X_test, y_train, y_test):
    """Builds, trains, and evaluates an Autoencoder model."""
    logging.info("Building and training Autoencoder model...")
    input_dim = X_train.shape[1]
    
    # Build the model
    input_layer = Input(shape=(input_dim,))
    encoder = Dense(64, activation="relu")(input_layer)
    encoder = Dense(32, activation="relu")(encoder)
    latent_view = Dense(16, activation="relu")(encoder)
    decoder = Dense(32, activation="relu")(latent_view)
    decoder = Dense(64, activation="relu")(decoder)
    output_layer = Dense(input_dim, activation="sigmoid")(decoder)
    
    autoencoder = Model(inputs=input_layer, outputs=output_layer)
    autoencoder.compile(optimizer="adam", loss="mae")
    
    # Train on normal data only
    early_stopping = EarlyStopping(
        monitor="val_loss", patience=10, restore_best_weights=True
    )
    autoencoder.fit(
        X_train[y_train == 0],
        X_train[y_train == 0],
        epochs=100,
        batch_size=32,
        shuffle=True,
        validation_data=(X_val[y_val == 0], X_val[y_val == 0]),
        callbacks=[early_stopping],
        verbose=1,
    )
    
    # Determine threshold for anomalies
    reconstruction_errors = np.mean(
        np.abs(X_val[y_val == 0] - autoencoder.predict(X_val[y_val == 0])), axis=1
    )
    threshold = np.mean(reconstruction_errors) + 2 * np.std(reconstruction_errors)
    
    # Predict on test data
    test_reconstruction_errors = np.mean(
        np.abs(X_test - autoencoder.predict(X_test)), axis=1
    )
    y_pred = [1 if e > threshold else 0 for e in test_reconstruction_errors]
    
    # Evaluate
    report = evaluate_model(y_test, y_pred, "Autoencoder")
    
    # Save model
    autoencoder.save(os.path.join(MODEL_DIR, "autoencoder_model.h5"))
    logging.info("Autoencoder model saved.")
    
    return report

def evaluate_model(y_true, y_pred, model_name):
    """Calculates and logs evaluation metrics."""
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)
    
    report = f"""
## {model_name} Evaluation Report
- **Accuracy**: {accuracy:.4f}
- **Precision**: {precision:.4f}
- **Recall**: {recall:.4f}
- **F1-score**: {f1:.4f}
- **False Positive Rate (FPR)**: {fpr:.4f}
- **False Negative Rate (FNR)**: {fnr:.4f}
- **Confusion Matrix**:
    - True Negatives: {tn}
    - False Positives: {fp}
    - False Negatives: {fn}
    - True Positives: {tp}
"""
    logging.info(f"Evaluation for {model_name}:\n{report}")
    return report

def generate_summary_report(reports):
    """Generates and saves a summary report of the model evaluations."""
    logging.info("Generating summary report...")
    
    summary = """
# Model Evaluation Summary

This report summarizes the performance of the anomaly detection models trained on the authentication and session security dataset.

"""
    for report in reports:
        summary += report
        
    summary += """
## Recommendations
- **Isolation Forest**: This model is computationally efficient and performs well in identifying anomalies without extensive tuning. It is a good baseline for general-purpose anomaly detection.
- **Autoencoder**: This model can capture complex patterns but requires careful tuning of the architecture and threshold. It may be more effective with larger datasets where intricate relationships exist.
- **Next Steps**: Consider ensembling both models to leverage their respective strengths. Further feature engineering and hyperparameter tuning could also improve performance.
"""
    
    report_path = os.path.join(DOCS_DIR, "model_evaluation_report.md")
    with open(report_path, "w") as f:
        f.write(summary)
        
    logging.info(f"Summary report saved to {report_path}")

if __name__ == "__main__":
    X_train, X_val, X_test, y_train, y_val, y_test = load_and_prepare_data()
    
    # Train and evaluate models
    if_report = train_isolation_forest(X_train, X_test, y_test)
    ae_report = train_autoencoder(X_train, X_val, X_test, y_train, y_test)
    
    # Generate and save the summary report
    generate_summary_report([if_report, ae_report])
    
    logging.info("Training and evaluation complete.")

