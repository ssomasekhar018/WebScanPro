
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
import numpy as np
import os
import datetime

# Create necessary directories
os.makedirs("projects/auth_session/ml", exist_ok=True)
os.makedirs("projects/auth_session/logs", exist_ok=True)
os.makedirs("projects/auth_session/docs", exist_ok=True)

# Generate a timestamp for the log file
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"projects/auth_session/logs/model_train_eval_{timestamp}.log"

def log_message(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

# 1. Load and Prepare Data
log_message("1. Loading and preparing data...")
try:
    df = pd.read_csv("projects/auth_session/data/feature_dataset.csv")
    log_message("Dataset loaded successfully.")
except FileNotFoundError:
    log_message("Error: feature_dataset.csv not found. Please ensure the dataset exists.")
    exit()

# Separate features and labels
X = df.drop("is_anomalous", axis=1)
y = df["is_anomalous"]

# Identify and remove non-numeric columns before scaling
numeric_cols = X.select_dtypes(include=np.number).columns.tolist()
X_numeric = X[numeric_cols]

# Normalize numerical features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_numeric)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42, stratify=y)
X_val, X_test, y_val, y_test = train_test_split(X_test, y_test, test_size=0.5, random_state=42)

# Separate normal data for training unsupervised models
X_train_normal = X_train[y_train == 0]
log_message("Data preparation and splitting complete.")

# 2. Train Anomaly Detection Models
log_message("\n2. Training anomaly detection models...")

# a. Isolation Forest
log_message("a. Training Isolation Forest model...")
iso_forest = IsolationForest(n_estimators=100, contamination='auto', max_samples='auto', random_state=42)
iso_forest.fit(X_train_normal)
log_message("Isolation Forest model training complete.")

# b. Autoencoder
log_message("b. Training Autoencoder model...")
input_dim = X_train_normal.shape[1]
encoding_dim = 16

input_layer = Input(shape=(input_dim,))
encoder = Dense(encoding_dim, activation="relu")(input_layer)
decoder = Dense(input_dim, activation="sigmoid")(encoder)
autoencoder = Model(inputs=input_layer, outputs=decoder)

autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.fit(X_train_normal, X_train_normal, epochs=50, batch_size=32, shuffle=True, validation_data=(X_val, X_val), verbose=0)
log_message("Autoencoder model training complete.")

# 3. Evaluate Model Performance
log_message("\n3. Evaluating model performance...")

# Evaluate Isolation Forest
y_pred_iso = iso_forest.predict(X_test)
y_pred_iso = [1 if pred == -1 else 0 for pred in y_pred_iso]

# Evaluate Autoencoder
reconstructions = autoencoder.predict(X_test)
mse = np.mean(np.power(X_test - reconstructions, 2), axis=1)
reconstruction_errors_normal = np.mean(np.power(X_train_normal - autoencoder.predict(X_train_normal), 2), axis=1)
threshold = np.mean(reconstruction_errors_normal) + 2 * np.std(reconstruction_errors_normal)
y_pred_auto = [1 if e > threshold else 0 for e in mse]

def evaluate(y_true, y_pred, model_name):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)
    
    log_message(f"\nEvaluation metrics for {model_name}:")
    log_message(f"Accuracy: {accuracy:.4f}")
    log_message(f"Precision: {precision:.4f}")
    log_message(f"Recall: {recall:.4f}")
    log_message(f"F1-score: {f1:.4f}")
    log_message(f"False Positive Rate: {fpr:.4f}")
    log_message(f"False Negative Rate: {fnr:.4f}")
    log_message(f"Confusion Matrix:\n{cm}")
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "fpr": fpr,
        "fnr": fnr,
        "cm": cm
    }

iso_metrics = evaluate(y_test, y_pred_iso, "Isolation Forest")
auto_metrics = evaluate(y_test, y_pred_auto, "Autoencoder")

# 4. Log and Document Results
log_message("\n4. Logging and documenting results...")

# Save models
import pickle
with open("projects/auth_session/ml/isolation_forest_model.pkl", "wb") as f:
    pickle.dump(iso_forest, f)
autoencoder.save("projects/auth_session/ml/autoencoder_model.h5")
with open("projects/auth_session/ml/preprocessing_pipeline.pkl", "wb") as f:
    pickle.dump(scaler, f)
log_message("Models and preprocessing pipeline saved successfully.")

# 5. Generate Evaluation Report
log_message("Generating evaluation report...")
report = f"""
# Model Evaluation Report

## Dataset Used
- **Source:** `projects/auth_session/data/feature_dataset.csv`
- **Shape:** {df.shape}

## Feature Set Overview
- **Features:** {list(X.columns)}

## Model Parameters
### Isolation Forest
- `n_estimators`: 100
- `contamination`: 'auto'
- `max_samples`: 'auto'

### Autoencoder
- **Architecture:** Input -> Dense(16, relu) -> Dense({input_dim}, sigmoid)
- **Optimizer:** Adam
- **Loss Function:** Mean Squared Error (MSE)
- **Epochs:** 50

## Key Results

### Isolation Forest
- **Accuracy:** {iso_metrics['accuracy']:.4f}
- **Precision:** {iso_metrics['precision']:.4f}
- **Recall:** {iso_metrics['recall']:.4f}
- **F1-score:** {iso_metrics['f1_score']:.4f}
- **False Positive Rate:** {iso_metrics['fpr']:.4f}
- **False Negative Rate:** {iso_metrics['fnr']:.4f}
- **Confusion Matrix:**
  ```
  {iso_metrics['cm']}
  ```

### Autoencoder
- **Accuracy:** {auto_metrics['accuracy']:.4f}
- **Precision:** {auto_metrics['precision']:.4f}
- **Recall:** {auto_metrics['recall']:.4f}
- **F1-score:** {auto_metrics['f1_score']:.4f}
- **False Positive Rate:** {auto_metrics['fpr']:.4f}
- **False Negative Rate:** {auto_metrics['fnr']:.4f}
- **Confusion Matrix:**
  ```
  {auto_metrics['cm']}
  ```

## Recommendations
- **Threshold Tuning:** The Autoencoder's performance is sensitive to the anomaly threshold. Further tuning could improve the trade-off between precision and recall.
- **Feature Pruning:** Analyze feature importance to see if a smaller feature set could yield similar or better results, reducing model complexity.
"""

with open("projects/auth_session/docs/model_evaluation_report.md", "w") as f:
    f.write(report)
log_message("Evaluation report generated successfully.")

print("Script finished successfully. Check logs and reports for details.")
