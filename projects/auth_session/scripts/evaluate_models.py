import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
import os

# Load dataset with predictions
df = pd.read_csv('data/anomaly_detection_results.csv')

# Calculate overlap
overlap = (df['anomaly_iforest'] == df['anomaly_ocsvm']).mean() * 100

# Save evaluation report
os.makedirs('outputs/reports', exist_ok=True)
with open('outputs/reports/evaluation_report.txt', 'w') as f:
    f.write("No ground-truth labels available.\n")
    f.write(f"Isolation Forest: {(df['anomaly_iforest'].sum() / len(df) * 100):.2f}% anomalies detected\n")
    f.write(f"One-Class SVM: {(df['anomaly_ocsvm'].sum() / len(df) * 100):.2f}% anomalies detected\n")
    f.write(f"Overlap in anomaly predictions: {overlap:.2f}%")
print("Evaluation report saved to 'outputs/reports/evaluation_report.txt'")