import sys
from pathlib import Path

# Add project root to the Python path
ROOT = Path(__file__).resolve().parents[3]
sys.path.append(str(ROOT))

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

from projects.sql_injection.scripts.feature_engineering import extract_features, get_preprocessor
from projects.sql_injection.scripts.config import DATASET_CSV   # will be created later

MODEL_DIR = ROOT / "projects" / "sql_injection" / "models"
MODEL_DIR.mkdir(exist_ok=True)

def main():
    df = pd.read_csv(DATASET_CSV)

    # Prepare data for feature extraction
    df = df.rename(columns={
        "input_value": "payload",
        "html_content_length": "html_len",
        "error_message_flag": "error_flag",
    })
    df["is_malicious"] = (df["label"] == "injection").astype(int)
    df["reflected_flag"] = 0  # Placeholder

    X_raw = extract_features(df)
    y = df["is_malicious"]

    X_train, X_test, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, stratify=y, random_state=42
    )

    scaler = get_preprocessor()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = RandomForestClassifier(n_estimators=400, random_state=42, n_jobs=-1)
    clf.fit(X_train_s, y_train)

    preds = clf.predict(X_test_s)
    probs = clf.predict_proba(X_test_s)[:, 1]

    print(classification_report(y_test, preds))
    print("ROC-AUC:", roc_auc_score(y_test, probs))

    # Save
    joblib.dump(clf, MODEL_DIR / "best_model.pkl")
    joblib.dump(scaler, MODEL_DIR / "preprocessor.pkl")
    print("SQLi model & preprocessor saved to", MODEL_DIR)

if __name__ == "__main__":
    main()