"""
IDOR Model Training & Evaluation (v2)
Trains:
  1. Isolation Forest  (unsupervised anomaly detection)
  2. Autoencoder       (deep unsupervised anomaly detection)
  3. Random Forest     (supervised — uses `is_unauthorized` label)

Uses the enriched feature set from feature_engineering_idor.py v2.
"""

import pandas as pd
import numpy as np
import pickle
import os
import datetime
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping

# Local import
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from projects.auth_session.feature_engineering_idor import run_feature_pipeline, FEATURE_COLS

# ── Directories ───────────────────────────────────────────────────────────────
ML_DIR   = "projects/auth_session/ml"
LOG_DIR  = "projects/auth_session/logs"
DOC_DIR  = "projects/auth_session/docs"
for d in [ML_DIR, LOG_DIR, DOC_DIR]:
    os.makedirs(d, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file  = os.path.join(LOG_DIR, f"model_train_eval_{timestamp}.log")

def log(msg: str):
    print(msg)
    with open(log_file, "a") as f:
        f.write(msg + "\n")


# ── 1. Load & Prepare Data ────────────────────────────────────────────────────
log("=" * 60)
log("IDOR Model Training & Evaluation v2")
log("=" * 60)
log("\n[1] Loading and preparing data...")

# Prefer synthetic dataset (larger); fall back to original
for candidate in [
    "projects/auth_session/data/idor_dataset_synthetic.csv",
    "projects/auth_session/data/feature_dataset.csv",
    "projects/auth_session/data/idor_dataset.csv",
]:
    if os.path.exists(candidate):
        DATA_PATH = candidate
        break
else:
    log("ERROR: No dataset found. Run create_synthetic_idor_dataset.py first.")
    raise SystemExit(1)

log(f"  Dataset: {DATA_PATH}")
df_raw = pd.read_csv(DATA_PATH)
log(f"  Shape: {df_raw.shape}")

# Run feature pipeline
df = run_feature_pipeline(df_raw)
log(f"  Feature columns ({len(FEATURE_COLS)}): {FEATURE_COLS}")

# Separate label
LABEL_COL = "is_unauthorized"
if LABEL_COL not in df.columns:
    log(f"ERROR: Label column '{LABEL_COL}' not found.")
    raise SystemExit(1)

y = df[LABEL_COL].astype(int)
X = df.drop(columns=[LABEL_COL], errors="ignore")

# Ensure numeric only
X = X.select_dtypes(include=np.number).fillna(0)
log(f"  Features used: {list(X.columns)}")
log(f"  Class distribution: {dict(y.value_counts())}")

# Scale
scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train/Val/Test split (70/15/15)
X_tr, X_tmp, y_tr, y_tmp = train_test_split(X_scaled, y, test_size=0.30, random_state=42, stratify=y)
X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp)

# Normal-only subset for unsupervised models
X_tr_normal = X_tr[y_tr == 0]
log(f"  Train: {len(X_tr)}, Val: {len(X_val)}, Test: {len(X_te)}")
log(f"  Normal-only train samples: {len(X_tr_normal)}")


# ── 2. Train Models ───────────────────────────────────────────────────────────
log("\n[2] Training models...")

# ── 2a. Isolation Forest ─────────────────────────────────────────────────────
log("  [2a] Isolation Forest...")
contamination = float(y_tr.mean())  # Use actual IDOR ratio
iso_forest = IsolationForest(
    n_estimators=200,
    contamination=contamination,
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
iso_forest.fit(X_tr_normal)
log(f"    Contamination set to: {contamination:.3f}")

# ── 2b. Autoencoder ───────────────────────────────────────────────────────────
log("  [2b] Autoencoder (TensorFlow)...")
input_dim    = X_tr_normal.shape[1]
encoding_dim = max(4, input_dim // 2)

inp     = Input(shape=(input_dim,))
encoded = Dense(encoding_dim, activation="relu")(inp)
encoded = BatchNormalization()(encoded)
encoded = Dropout(0.2)(encoded)
encoded = Dense(encoding_dim // 2, activation="relu")(encoded)
decoded = Dense(encoding_dim, activation="relu")(encoded)
decoded = Dense(input_dim, activation="sigmoid")(decoded)

autoencoder = Model(inputs=inp, outputs=decoded)
autoencoder.compile(optimizer="adam", loss="mse")

early_stop = EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True)
autoencoder.fit(
    X_tr_normal, X_tr_normal,
    epochs=100,
    batch_size=32,
    shuffle=True,
    validation_data=(X_val, X_val),
    callbacks=[early_stop],
    verbose=0,
)
log("    Autoencoder training complete.")

# ── 2c. Random Forest (Supervised) ───────────────────────────────────────────
log("  [2c] Random Forest (supervised)...")
rf_model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
rf_model.fit(X_tr, y_tr)
log("    Random Forest training complete.")

# Cross-validation
cv_scores = cross_val_score(rf_model, X_tr, y_tr, cv=5, scoring="f1", n_jobs=-1)
log(f"    CV F1 scores: {cv_scores.round(4)} — mean: {cv_scores.mean():.4f}")


# ── 3. Evaluate ───────────────────────────────────────────────────────────────
log("\n[3] Evaluating models on test set...")

def evaluate(y_true, y_pred, model_name, y_prob=None):
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    cm   = confusion_matrix(y_true, y_pred)

    auc = None
    if y_prob is not None:
        try:
            auc = roc_auc_score(y_true, y_prob)
        except Exception:
            pass

    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

    log(f"\n  [{model_name}]")
    log(f"    Accuracy : {acc:.4f}")
    log(f"    Precision: {prec:.4f}")
    log(f"    Recall   : {rec:.4f}")
    log(f"    F1-score : {f1:.4f}")
    if auc is not None:
        log(f"    AUC-ROC  : {auc:.4f}")
    log(f"    FPR      : {fpr:.4f}   FNR: {fnr:.4f}")
    log(f"    Confusion Matrix:\n{cm}")

    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
            "auc": auc, "fpr": fpr, "fnr": fnr, "cm": cm}


# Isolation Forest
y_pred_iso = iso_forest.predict(X_te)
y_pred_iso_bin = [1 if p == -1 else 0 for p in y_pred_iso]
iso_scores_raw = iso_forest.decision_function(X_te)
iso_prob = 1 - (iso_scores_raw - iso_scores_raw.min()) / (iso_scores_raw.max() - iso_scores_raw.min() + 1e-9)
iso_metrics = evaluate(y_te, y_pred_iso_bin, "Isolation Forest", iso_prob)

# Autoencoder
recon = autoencoder.predict(X_te, verbose=0)
mse   = np.mean(np.power(X_te - recon, 2), axis=1)
normal_recon = autoencoder.predict(X_tr_normal, verbose=0)
normal_mse   = np.mean(np.power(X_tr_normal - normal_recon, 2), axis=1)
ae_threshold = np.mean(normal_mse) + 2.0 * np.std(normal_mse)
y_pred_ae    = [1 if e > ae_threshold else 0 for e in mse]
ae_prob      = (mse - mse.min()) / (mse.max() - mse.min() + 1e-9)
ae_metrics   = evaluate(y_te, y_pred_ae, "Autoencoder", ae_prob)

# Random Forest
y_pred_rf = rf_model.predict(X_te)
y_prob_rf  = rf_model.predict_proba(X_te)[:, 1]
rf_metrics = evaluate(y_te, y_pred_rf, "Random Forest", y_prob_rf)
log("\n  Random Forest — Full Classification Report:")
log(classification_report(y_te, y_pred_rf))

# Feature importance
feat_names = list(X.columns)
importances = pd.Series(rf_model.feature_importances_, index=feat_names).sort_values(ascending=False)
log("\n  Random Forest — Top 10 Feature Importances:")
for feat, imp in importances.head(10).items():
    log(f"    {feat:<30} {imp:.4f}")


# ── 4. Save Models ────────────────────────────────────────────────────────────
log("\n[4] Saving models...")

with open(os.path.join(ML_DIR, "isolation_forest_model.pkl"), "wb") as f:
    pickle.dump(iso_forest, f)
log("  Saved: isolation_forest_model.pkl")

autoencoder.save(os.path.join(ML_DIR, "autoencoder_model.h5"))
log("  Saved: autoencoder_model.h5")

joblib.dump(rf_model, os.path.join(ML_DIR, "random_forest_idor.joblib"))
log("  Saved: random_forest_idor.joblib")

with open(os.path.join(ML_DIR, "preprocessing_pipeline.pkl"), "wb") as f:
    pickle.dump(scaler, f)
log("  Saved: preprocessing_pipeline.pkl")

# Save the best model alias (Random Forest usually wins on supervised tasks)
best_model = rf_model
joblib.dump(best_model, os.path.join(ML_DIR, "idor_model.joblib"))
log("  Saved: idor_model.joblib  (best model alias)")


# ── 5. Write Evaluation Report ────────────────────────────────────────────────
log("\n[5] Generating evaluation report...")

def _fmt(v):
    return f"{v:.4f}" if v is not None else "N/A"

report = f"""# IDOR Model Evaluation Report (v2)
Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Dataset
- **Source**: `{DATA_PATH}`
- **Shape**: {df_raw.shape}
- **IDOR Ratio**: {y.mean() * 100:.1f}%

## Feature Set ({len(X.columns)} features)
{chr(10).join(f"- `{c}`" for c in X.columns)}

## Results

| Metric     | Isolation Forest | Autoencoder | Random Forest |
|------------|-----------------|-------------|---------------|
| Accuracy   | {_fmt(iso_metrics['accuracy'])} | {_fmt(ae_metrics['accuracy'])} | {_fmt(rf_metrics['accuracy'])} |
| Precision  | {_fmt(iso_metrics['precision'])} | {_fmt(ae_metrics['precision'])} | {_fmt(rf_metrics['precision'])} |
| Recall     | {_fmt(iso_metrics['recall'])} | {_fmt(ae_metrics['recall'])} | {_fmt(rf_metrics['recall'])} |
| F1-score   | {_fmt(iso_metrics['f1'])} | {_fmt(ae_metrics['f1'])} | {_fmt(rf_metrics['f1'])} |
| AUC-ROC    | {_fmt(iso_metrics['auc'])} | {_fmt(ae_metrics['auc'])} | {_fmt(rf_metrics['auc'])} |
| FPR        | {_fmt(iso_metrics['fpr'])} | {_fmt(ae_metrics['fpr'])} | {_fmt(rf_metrics['fpr'])} |
| FNR        | {_fmt(iso_metrics['fnr'])} | {_fmt(ae_metrics['fnr'])} | {_fmt(rf_metrics['fnr'])} |

## Top Feature Importances (Random Forest)
{chr(10).join(f"- `{feat}`: {imp:.4f}" for feat, imp in importances.head(10).items())}

## Recommendations
- **Random Forest** is the recommended production model (supervised, interpretable).
- Isolation Forest is useful for zero-shot anomaly detection on new endpoints.
- Autoencoder threshold can be tuned to reduce FPR.
"""

report_path = os.path.join(DOC_DIR, "model_evaluation_report_v2.md")
with open(report_path, "w") as f:
    f.write(report)
log(f"  Report saved: {report_path}")
log("\nTraining complete!")
