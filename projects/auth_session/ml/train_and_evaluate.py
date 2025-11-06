#!/usr/bin/env python3
"""
Train and Evaluate Anomaly Detection Models for Authentication & Session Security.

Trains two models:
1. Isolation Forest (unsupervised)
2. Autoencoder (unsupervised)

Evaluates both models and generates comprehensive reports.
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Tuple

# ML libraries
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve,
    confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
import joblib

# Deep learning libraries
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model, callbacks
    TENSORFLOW_AVAILABLE = True
except ImportError:
    print("WARNING: TensorFlow not available. Autoencoder model will be skipped.")
    TENSORFLOW_AVAILABLE = False

# Matplotlib for plotting
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    print("WARNING: Matplotlib not available. Plots will be skipped.")
    PLOTTING_AVAILABLE = False

# Add parent directories to path
# __file__ is in projects/auth_session/ml/, so go up 3 levels to project-root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
AUTH_SESSION_DIR = os.path.join(BASE_DIR, "projects", "auth_session")
DATA_DIR = os.path.join(AUTH_SESSION_DIR, "data")
ML_DIR = os.path.join(AUTH_SESSION_DIR, "ml")
LOGS_DIR = os.path.join(AUTH_SESSION_DIR, "logs")
DOCS_DIR = os.path.join(AUTH_SESSION_DIR, "docs")

# Ensure directories exist
for d in [ML_DIR, LOGS_DIR, DOCS_DIR]:
    os.makedirs(d, exist_ok=True)

# File paths
FEATURE_DATASET = os.path.join(DATA_DIR, "feature_dataset.csv")
ISOLATION_FOREST_MODEL = os.path.join(ML_DIR, "isolation_forest_model.pkl")
AUTOENCODER_MODEL = os.path.join(ML_DIR, "autoencoder_model.h5")
SCALER_MODEL = os.path.join(ML_DIR, "scaler.pkl")
ONECLASS_SVM_MODEL = os.path.join(ML_DIR, "oneclass_svm_model.pkl")

# Logging
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(LOGS_DIR, f"model_train_eval_{timestamp}.log")

def log(msg, level="INFO"):
    """Log message to console and file."""
    ts = datetime.now().isoformat()
    log_msg = f"[{ts}] [{level}] {msg}"
    print(log_msg)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


class AnomalyDetectionTrainer:
    """Train and evaluate anomaly detection models."""
    
    def __init__(self, dataset_path: str = FEATURE_DATASET):
        self.dataset_path = dataset_path
        self.df = None
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None
        self.feature_names = None
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.autoencoder = None
        self.oneclass_svm = None
        self.results = {}
        
    def load_and_prepare_data(self, test_size: float = 0.15, val_size: float = 0.15):
        """Load dataset and prepare train/validation/test splits."""
        log("Loading dataset...")
        
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")
            
        self.df = pd.read_csv(self.dataset_path)
        log(f"Loaded dataset: {len(self.df)} rows, {len(self.df.columns)} columns")
        
        # Validate dataset
        if "is_anomalous" not in self.df.columns:
            raise ValueError("Dataset must contain 'is_anomalous' column")
            
        # Get feature columns (exclude labels and identifiers)
        exclude_cols = [
            "event_id", "timestamp", "username_anon", "ip_address_anon",
            "is_anomalous", "is_bruteforce_candidate", "auth_result"
        ]
        
        feature_cols = [c for c in self.df.columns if c not in exclude_cols]
        
        # Select only numeric features
        numeric_cols = [c for c in feature_cols if self.df[c].dtype in ['int64', 'float64']]
        self.feature_names = numeric_cols
        
        log(f"Selected {len(numeric_cols)} numeric features")
        
        # Prepare features and labels
        X = self.df[numeric_cols].fillna(0).values
        y = self.df["is_anomalous"].values
        
        log(f"Feature shape: {X.shape}")
        log(f"Label distribution: {np.bincount(y)}")
        
        # Split data: 70% train, 15% val, 15% test
        # First split: train (70%) + temp (30%)
        from sklearn.model_selection import train_test_split
        
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Second split: train (70%) + val (15%)
        val_size_adjusted = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_size_adjusted, random_state=42, stratify=y_temp
        )
        
        self.X_train = X_train
        self.X_val = X_val
        self.X_test = X_test
        self.y_train = y_train
        self.y_val = y_val
        self.y_test = y_test
        
        log(f"Train: {len(X_train)} samples ({np.bincount(y_train)})")
        log(f"Validation: {len(X_val)} samples ({np.bincount(y_val)})")
        log(f"Test: {len(X_test)} samples ({np.bincount(y_test)})")
        
        # For unsupervised learning, train on normal data only
        # But we'll also use validation/test sets for evaluation
        self.X_train_normal = X_train[y_train == 0]
        log(f"Training on normal data only: {len(self.X_train_normal)} samples")
        
        # Scale features
        log("Scaling features...")
        self.X_train_scaled = self.scaler.fit_transform(X_train)
        self.X_val_scaled = self.scaler.transform(X_val)
        self.X_test_scaled = self.scaler.transform(X_test)
        self.X_train_normal_scaled = self.scaler.transform(self.X_train_normal)
        
        # Save scaler
        joblib.dump(self.scaler, SCALER_MODEL)
        log(f"Scaler saved to {SCALER_MODEL}")
        
    def train_isolation_forest(self, n_estimators: int = 100, contamination: float = 0.1):
        """Train Isolation Forest model."""
        log("=" * 60)
        log("Training Isolation Forest model...")
        
        # Isolation Forest parameters
        self.isolation_forest = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
        # Train on normal data
        log(f"Training on {len(self.X_train_normal_scaled)} normal samples...")
        self.isolation_forest.fit(self.X_train_normal_scaled)
        
        log("Isolation Forest training complete")
        
        # Save model
        joblib.dump(self.isolation_forest, ISOLATION_FOREST_MODEL)
        log(f"Isolation Forest model saved to {ISOLATION_FOREST_MODEL}")

    def train_oneclass_svm(self, kernel: str = "rbf", nu: float = 0.1, gamma: str | float = "scale"):
        """Train One-Class SVM model on normal data."""
        log("=" * 60)
        log("Training One-Class SVM model...")

        self.oneclass_svm = OneClassSVM(kernel=kernel, nu=nu, gamma=gamma)

        log(f"Training on {len(self.X_train_normal_scaled)} normal samples...")
        self.oneclass_svm.fit(self.X_train_normal_scaled)

        joblib.dump(self.oneclass_svm, ONECLASS_SVM_MODEL)
        log(f"One-Class SVM model saved to {ONECLASS_SVM_MODEL}")
        
    def train_autoencoder(self, epochs: int = 100, batch_size: int = 32):
        """Train Autoencoder model."""
        if not TENSORFLOW_AVAILABLE:
            log("Skipping Autoencoder training (TensorFlow not available)", "WARNING")
            return
            
        log("=" * 60)
        log("Training Autoencoder model...")
        
        input_dim = self.X_train_normal_scaled.shape[1]
        encoding_dim = max(8, input_dim // 4)  # Encoding dimension
        
        log(f"Input dimension: {input_dim}, Encoding dimension: {encoding_dim}")
        
        # Build autoencoder
        input_layer = layers.Input(shape=(input_dim,))
        encoder = layers.Dense(encoding_dim * 2, activation='relu')(input_layer)
        encoder = layers.Dense(encoding_dim, activation='relu')(encoder)
        decoder = layers.Dense(encoding_dim * 2, activation='relu')(encoder)
        decoder = layers.Dense(input_dim, activation='linear')(decoder)
        
        self.autoencoder = Model(input_layer, decoder)
        self.autoencoder.compile(optimizer='adam', loss='mse')
        
        log("Autoencoder architecture:")
        self.autoencoder.summary(print_fn=lambda x: log(f"  {x}"))
        
        # Callbacks
        early_stopping = callbacks.EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        )
        
        # Train on normal data
        log(f"Training on {len(self.X_train_normal_scaled)} normal samples for {epochs} epochs...")
        
        # Split normal data for validation
        from sklearn.model_selection import train_test_split
        X_train_ae, X_val_ae, _, _ = train_test_split(
            self.X_train_normal_scaled, 
            np.zeros(len(self.X_train_normal_scaled)),
            test_size=0.2,
            random_state=42
        )
        
        history = self.autoencoder.fit(
            X_train_ae, X_train_ae,
            validation_data=(X_val_ae, X_val_ae),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping],
            verbose=0
        )
        
        log(f"Training completed. Best val loss: {min(history.history['val_loss']):.6f}")
        
        # Save model
        self.autoencoder.save(AUTOENCODER_MODEL)
        log(f"Autoencoder model saved to {AUTOENCODER_MODEL}")
        
    def evaluate_model(self, model_type: str = "isolation_forest"):
        """Evaluate a model and return metrics."""
        if model_type == "isolation_forest":
            if self.isolation_forest is None:
                raise ValueError("Isolation Forest model not trained")
            
            # Predict on test set
            predictions = self.isolation_forest.predict(self.X_test_scaled)
            # Convert: -1 (anomaly) -> 1, 1 (normal) -> 0
            y_pred = (predictions == -1).astype(int)
            # Decision scores (negative scores = more anomalous)
            scores = -self.isolation_forest.score_samples(self.X_test_scaled)
            
        elif model_type == "autoencoder":
            if self.autoencoder is None:
                raise ValueError("Autoencoder model not trained")
            
            # Reconstruct test data
            reconstructions = self.autoencoder.predict(self.X_test_scaled, verbose=0)
            # Calculate reconstruction error (MSE)
            mse = np.mean(np.power(self.X_test_scaled - reconstructions, 2), axis=1)
            scores = mse
            
            # Threshold: use 95th percentile of training normal data
            train_reconstructions = self.autoencoder.predict(self.X_train_normal_scaled, verbose=0)
            train_mse = np.mean(np.power(self.X_train_normal_scaled - train_reconstructions, 2), axis=1)
            threshold = np.percentile(train_mse, 95)
            
            y_pred = (mse > threshold).astype(int)
            
        elif model_type == "oneclass_svm":
            if self.oneclass_svm is None:
                raise ValueError("One-Class SVM model not trained")

            predictions = self.oneclass_svm.predict(self.X_test_scaled)
            y_pred = (predictions == -1).astype(int)
            # Use signed distance to the separating hyperplane as anomaly score
            scores = -self.oneclass_svm.decision_function(self.X_test_scaled)

        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        # Calculate metrics
        y_true = self.y_test
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # ROC AUC (convert scores to probabilities)
        try:
            # Normalize scores to [0, 1] for ROC
            scores_normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
            auc_roc = roc_auc_score(y_true, scores_normalized)
            fpr, tpr, _ = roc_curve(y_true, scores_normalized)
        except:
            auc_roc = 0.0
            fpr, tpr = np.array([0, 1]), np.array([0, 1])
        
        # Precision-Recall curve
        try:
            precision_curve, recall_curve, _ = precision_recall_curve(y_true, scores_normalized)
            from sklearn.metrics import auc
            auc_pr = auc(recall_curve, precision_curve)
        except Exception as e:
            log(f"PR-AUC calculation error: {e}", "WARNING")
            auc_pr = 0.0
            precision_curve, recall_curve = np.array([1, 0]), np.array([0, 1])
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        
        metrics = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": auc_roc,
            "pr_auc": auc_pr,
            "fpr": fpr_rate,
            "fnr": fnr_rate,
            "true_positives": int(tp),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "confusion_matrix": cm.tolist(),
            "fpr_curve": fpr.tolist(),
            "tpr_curve": tpr.tolist(),
            "precision_curve": precision_curve.tolist(),
            "recall_curve": recall_curve.tolist(),
        }
        
        return metrics, y_pred, scores
    
    def generate_plots(self, if_metrics: Dict, ae_metrics: Dict, ocsvm_metrics: Dict | None):
        """Generate evaluation plots."""
        if not PLOTTING_AVAILABLE:
            log("Skipping plot generation (Matplotlib not available)", "WARNING")
            return
            
        log("Generating evaluation plots...")
        
        plots_dir = os.path.join(DOCS_DIR, "plots")
        os.makedirs(plots_dir, exist_ok=True)
        
        # Set style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (10, 6)
        
        # 1. ROC Curves
        fig, ax = plt.subplots()
        ax.plot(if_metrics["fpr_curve"], if_metrics["tpr_curve"], 
                label=f'Isolation Forest (AUC = {if_metrics["roc_auc"]:.3f})', linewidth=2)
        if ae_metrics:
            ax.plot(ae_metrics["fpr_curve"], ae_metrics["tpr_curve"],
                    label=f'Autoencoder (AUC = {ae_metrics["roc_auc"]:.3f})', linewidth=2)
        if ocsvm_metrics:
            ax.plot(ocsvm_metrics["fpr_curve"], ocsvm_metrics["tpr_curve"],
                    label=f'One-Class SVM (AUC = {ocsvm_metrics["roc_auc"]:.3f})', linewidth=2)
        ax.plot([0, 1], [0, 1], 'k--', label='Random', linewidth=1)
        ax.set_xlabel('False Positive Rate', fontsize=12)
        ax.set_ylabel('True Positive Rate', fontsize=12)
        ax.set_title('ROC Curves - Anomaly Detection Models', fontsize=14, fontweight='bold')
        ax.legend(loc='lower right', fontsize=10)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, "roc_curves.png"), dpi=300, bbox_inches='tight')
        plt.close()
        log(f"Saved ROC curves to {plots_dir}/roc_curves.png")
        
        # 2. Precision-Recall Curves
        fig, ax = plt.subplots()
        ax.plot(if_metrics["recall_curve"], if_metrics["precision_curve"],
                label=f'Isolation Forest (AUC = {if_metrics["pr_auc"]:.3f})', linewidth=2)
        if ae_metrics:
            ax.plot(ae_metrics["recall_curve"], ae_metrics["precision_curve"],
                    label=f'Autoencoder (AUC = {ae_metrics["pr_auc"]:.3f})', linewidth=2)
        if ocsvm_metrics:
            ax.plot(ocsvm_metrics["recall_curve"], ocsvm_metrics["precision_curve"],
                    label=f'One-Class SVM (AUC = {ocsvm_metrics["pr_auc"]:.3f})', linewidth=2)
        ax.set_xlabel('Recall', fontsize=12)
        ax.set_ylabel('Precision', fontsize=12)
        ax.set_title('Precision-Recall Curves - Anomaly Detection Models', fontsize=14, fontweight='bold')
        ax.legend(loc='lower left', fontsize=10)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, "pr_curves.png"), dpi=300, bbox_inches='tight')
        plt.close()
        log(f"Saved PR curves to {plots_dir}/pr_curves.png")
        
        # 3. Confusion Matrices
        fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        
        # Isolation Forest
        sns.heatmap(if_metrics["confusion_matrix"], annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Normal', 'Anomalous'], yticklabels=['Normal', 'Anomalous'],
                   ax=axes[0])
        axes[0].set_title('Isolation Forest', fontsize=12, fontweight='bold')
        axes[0].set_ylabel('True Label', fontsize=10)
        axes[0].set_xlabel('Predicted Label', fontsize=10)
        
        # Autoencoder
        if ae_metrics:
            sns.heatmap(ae_metrics["confusion_matrix"], annot=True, fmt='d', cmap='Oranges',
                       xticklabels=['Normal', 'Anomalous'], yticklabels=['Normal', 'Anomalous'],
                       ax=axes[1])
            axes[1].set_title('Autoencoder', fontsize=12, fontweight='bold')
            axes[1].set_ylabel('True Label', fontsize=10)
            axes[1].set_xlabel('Predicted Label', fontsize=10)
        else:
            axes[1].text(0.5, 0.5, 'Autoencoder\nNot Available', 
                        ha='center', va='center', fontsize=12)
            axes[1].set_title('Autoencoder', fontsize=12, fontweight='bold')

        # One-Class SVM
        if ocsvm_metrics:
            sns.heatmap(ocsvm_metrics["confusion_matrix"], annot=True, fmt='d', cmap='Greens',
                       xticklabels=['Normal', 'Anomalous'], yticklabels=['Normal', 'Anomalous'],
                       ax=axes[2])
            axes[2].set_title('One-Class SVM', fontsize=12, fontweight='bold')
            axes[2].set_ylabel('True Label', fontsize=10)
            axes[2].set_xlabel('Predicted Label', fontsize=10)
        else:
            axes[2].text(0.5, 0.5, 'One-Class SVM\nNot Available',
                        ha='center', va='center', fontsize=12)
            axes[2].set_title('One-Class SVM', fontsize=12, fontweight='bold')
        
        plt.suptitle('Confusion Matrices', fontsize=14, fontweight='bold', y=1.02)
        plt.tight_layout()
        plt.savefig(os.path.join(plots_dir, "confusion_matrices.png"), dpi=300, bbox_inches='tight')
        plt.close()
        log(f"Saved confusion matrices to {plots_dir}/confusion_matrices.png")
        
    def run_training_and_evaluation(self):
        """Run complete training and evaluation pipeline."""
        log("=" * 60)
        log("Starting ML Model Training and Evaluation")
        log("=" * 60)
        
        # Load and prepare data
        self.load_and_prepare_data()
        
        # Train models
        self.train_isolation_forest(n_estimators=100, contamination=0.1)
        self.train_oneclass_svm(kernel="rbf", nu=0.1, gamma="scale")
        
        if TENSORFLOW_AVAILABLE:
            self.train_autoencoder(epochs=100, batch_size=32)
        
        # Evaluate models
        log("=" * 60)
        log("Evaluating models...")
        
        if_metrics, _, _ = self.evaluate_model("isolation_forest")
        self.results["isolation_forest"] = if_metrics
        
        ae_metrics = None
        if TENSORFLOW_AVAILABLE and self.autoencoder is not None:
            ae_metrics, _, _ = self.evaluate_model("autoencoder")
            self.results["autoencoder"] = ae_metrics
        ocsvm_metrics, _, _ = self.evaluate_model("oneclass_svm")
        self.results["oneclass_svm"] = ocsvm_metrics
        
        # Generate plots
        self.generate_plots(if_metrics, ae_metrics, ocsvm_metrics)
        
        # Print summary
        log("=" * 60)
        log("Evaluation Summary")
        log("=" * 60)
        
        log("\nIsolation Forest:")
        log(f"  Accuracy: {if_metrics['accuracy']:.4f}")
        log(f"  Precision: {if_metrics['precision']:.4f}")
        log(f"  Recall: {if_metrics['recall']:.4f}")
        log(f"  F1-Score: {if_metrics['f1_score']:.4f}")
        log(f"  ROC-AUC: {if_metrics['roc_auc']:.4f}")
        log(f"  PR-AUC: {if_metrics['pr_auc']:.4f}")
        log(f"  FPR: {if_metrics['fpr']:.4f}")
        log(f"  FNR: {if_metrics['fnr']:.4f}")
        
        if ae_metrics:
            log("\nAutoencoder:")
            log(f"  Accuracy: {ae_metrics['accuracy']:.4f}")
            log(f"  Precision: {ae_metrics['precision']:.4f}")
            log(f"  Recall: {ae_metrics['recall']:.4f}")
            log(f"  F1-Score: {ae_metrics['f1_score']:.4f}")
            log(f"  ROC-AUC: {ae_metrics['roc_auc']:.4f}")
            log(f"  PR-AUC: {ae_metrics['pr_auc']:.4f}")
            log(f"  FPR: {ae_metrics['fpr']:.4f}")
            log(f"  FNR: {ae_metrics['fnr']:.4f}")

        log("\nOne-Class SVM:")
        log(f"  Accuracy: {ocsvm_metrics['accuracy']:.4f}")
        log(f"  Precision: {ocsvm_metrics['precision']:.4f}")
        log(f"  Recall: {ocsvm_metrics['recall']:.4f}")
        log(f"  F1-Score: {ocsvm_metrics['f1_score']:.4f}")
        log(f"  ROC-AUC: {ocsvm_metrics['roc_auc']:.4f}")
        log(f"  PR-AUC: {ocsvm_metrics['pr_auc']:.4f}")
        log(f"  FPR: {ocsvm_metrics['fpr']:.4f}")
        log(f"  FNR: {ocsvm_metrics['fnr']:.4f}")
        
        return self.results


def main():
    """Main entry point."""
    trainer = AnomalyDetectionTrainer()
    results = trainer.run_training_and_evaluation()
    
    log("\n" + "=" * 60)
    log("Training and Evaluation Complete!")
    log("=" * 60)
    
    return results


if __name__ == "__main__":
    main()

