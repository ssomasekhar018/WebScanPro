# projects/sql_injection/scripts/train_and_evaluate_models.py
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from pathlib import Path

from projects.sql_injection.scripts.feature_engineering import extract_features, get_preprocessor
from projects.sql_injection.scanner.config import DATASET_CSV   # will be created later

ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

def main():
    df = pd.read_csv(DATASET_CSV)
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