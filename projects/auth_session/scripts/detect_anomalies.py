import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import os

# Load dataset
data_path = 'data/cleaned_dataset.csv'
df = pd.read_csv(data_path)

# Prepare data
feature_cols = ['input_length', 'num_special_chars', 'num_digits', 
                'url_encoded', 'parameter_encoded', 'param_type_encoded', 
                'contains_sql_keyword', 'contains_html_tag']
X = df[feature_cols]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest
iforest = IsolationForest(contamination=0.1, random_state=42)
iforest.fit(X_scaled)
df['anomaly_iforest'] = iforest.predict(X_scaled)
df['anomaly_iforest'] = df['anomaly_iforest'].map({1: 0, -1: 1})
joblib.dump(iforest, 'models/isolation_forest_model.pkl')

# Train One-Class SVM
ocsvm = OneClassSVM(nu=0.1, kernel='rbf', gamma='auto')
ocsvm.fit(X_scaled)
df['anomaly_ocsvm'] = ocsvm.predict(X_scaled)
df['anomaly_ocsvm'] = df['anomaly_ocsvm'].map({1: 0, -1: 1})
joblib.dump(ocsvm, 'models/oneclass_svm_model.pkl')

# Save updated dataset
df.to_csv('data/anomaly_detection_results.csv', index=False)
print("Anomaly detection completed. Results saved to 'data/anomaly_detection_results.csv'")