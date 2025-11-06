"""
Model Preparation Utilities for Authentication & Session Security Dataset.

Utility functions for preparing dataset for ML model training:
- Train/test splitting
- Feature scaling/normalization
- Class balancing
- Data validation
"""

import pandas as pd
import numpy as np
from typing import Tuple, Optional, Dict, List
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.utils import resample
import os

# Add parent directory to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "projects", "auth_session", "data")
FEATURE_DATASET = os.path.join(DATA_DIR, "feature_dataset.csv")


class DatasetPreparator:
    """Prepares dataset for ML model training."""
    
    def __init__(self, dataset_path: str = FEATURE_DATASET):
        self.dataset_path = dataset_path
        self.df = None
        self.scaler = None
        
    def load_dataset(self) -> pd.DataFrame:
        """Load feature dataset."""
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")
            
        self.df = pd.read_csv(self.dataset_path)
        print(f"Loaded dataset: {len(self.df)} rows, {len(self.df.columns)} columns")
        return self.df
        
    def validate_dataset(self) -> Dict[str, bool]:
        """Validate dataset quality."""
        if self.df is None:
            self.load_dataset()
            
        validation_results = {
            "has_data": len(self.df) > 0,
            "has_labels": "is_anomalous" in self.df.columns,
            "no_null_labels": self.df["is_anomalous"].notna().all() if "is_anomalous" in self.df.columns else False,
            "has_features": len([c for c in self.df.columns if c not in ["event_id", "timestamp", "is_anomalous", "is_bruteforce_candidate"]]) > 0,
            "label_distribution": None,
        }
        
        if validation_results["has_labels"]:
            label_counts = self.df["is_anomalous"].value_counts()
            validation_results["label_distribution"] = {
                "normal": int(label_counts.get(0, 0)),
                "anomalous": int(label_counts.get(1, 0)),
                "anomaly_rate": float(label_counts.get(1, 0) / len(self.df)) if len(self.df) > 0 else 0.0
            }
            
        return validation_results
        
    def get_feature_columns(self, exclude: Optional[List[str]] = None) -> List[str]:
        """Get list of feature columns (excluding identifiers and labels)."""
        if self.df is None:
            self.load_dataset()
            
        exclude_cols = exclude or ["event_id", "timestamp", "username_anon", "ip_address_anon", 
                                   "is_anomalous", "is_bruteforce_candidate", "auth_result"]
        feature_cols = [c for c in self.df.columns if c not in exclude_cols]
        return feature_cols
        
    def prepare_features_and_labels(self, feature_cols: Optional[List[str]] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare feature matrix X and label vector y."""
        if self.df is None:
            self.load_dataset()
            
        if feature_cols is None:
            feature_cols = self.get_feature_columns()
            
        # Select numeric features only
        numeric_cols = [c for c in feature_cols if self.df[c].dtype in ['int64', 'float64']]
        
        X = self.df[numeric_cols].fillna(0).values
        y = self.df["is_anomalous"].values if "is_anomalous" in self.df.columns else None
        
        if y is None:
            raise ValueError("Label column 'is_anomalous' not found in dataset")
            
        return X, y, numeric_cols
        
    def split_train_test(self, X: np.ndarray, y: np.ndarray, 
                        test_size: float = 0.2, random_state: int = 42,
                        temporal_split: bool = True) -> Tuple:
        """
        Split dataset into train and test sets.
        
        Args:
            temporal_split: If True, split by time (first 80% train, last 20% test)
                          If False, use random split
        """
        if temporal_split and self.df is not None and "timestamp" in self.df.columns:
            # Temporal split: earlier events = train, later events = test
            split_idx = int(len(X) * (1 - test_size))
            X_train = X[:split_idx]
            X_test = X[split_idx:]
            y_train = y[:split_idx]
            y_test = y[split_idx:]
        else:
            # Random split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
        return X_train, X_test, y_train, y_test
        
    def scale_features(self, X_train: np.ndarray, X_test: np.ndarray,
                      scaler_type: str = "standard") -> Tuple[np.ndarray, np.ndarray, object]:
        """
        Scale features using StandardScaler or MinMaxScaler.
        
        Args:
            scaler_type: "standard" for StandardScaler, "minmax" for MinMaxScaler
        """
        if scaler_type == "standard":
            self.scaler = StandardScaler()
        elif scaler_type == "minmax":
            self.scaler = MinMaxScaler()
        else:
            raise ValueError(f"Unknown scaler type: {scaler_type}")
            
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, self.scaler
        
    def balance_dataset(self, X: np.ndarray, y: np.ndarray, 
                       method: str = "upsample") -> Tuple[np.ndarray, np.ndarray]:
        """
        Balance dataset using upsampling or downsampling.
        
        Args:
            method: "upsample" to oversample minority class, "downsample" to undersample majority class
        """
        # Combine X and y for resampling
        df_combined = pd.DataFrame(X)
        df_combined["label"] = y
        
        # Separate classes
        df_majority = df_combined[df_combined["label"] == 0]
        df_minority = df_combined[df_combined["label"] == 1]
        
        if method == "upsample":
            # Upsample minority class
            df_minority_upsampled = resample(
                df_minority, replace=True, n_samples=len(df_majority), random_state=42
            )
            df_balanced = pd.concat([df_majority, df_minority_upsampled])
        elif method == "downsample":
            # Downsample majority class
            df_majority_downsampled = resample(
                df_majority, replace=False, n_samples=len(df_minority), random_state=42
            )
            df_balanced = pd.concat([df_minority, df_majority_downsampled])
        else:
            raise ValueError(f"Unknown method: {method}")
            
        # Shuffle
        df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Separate features and labels
        X_balanced = df_balanced.drop("label", axis=1).values
        y_balanced = df_balanced["label"].values
        
        return X_balanced, y_balanced
        
    def prepare_for_training(self, test_size: float = 0.2, scale: bool = True,
                           balance: bool = False, temporal_split: bool = True) -> Dict:
        """
        Complete pipeline: load, validate, prepare, split, scale, balance.
        
        Returns dictionary with:
            - X_train, X_test, y_train, y_test
            - feature_names
            - scaler (if scaling applied)
            - validation_results
        """
        # Load and validate
        self.load_dataset()
        validation = self.validate_dataset()
        print(f"Validation: {validation}")
        
        if not validation["has_data"]:
            raise ValueError("Dataset is empty")
            
        # Prepare features
        X, y, feature_names = self.prepare_features_and_labels()
        print(f"Prepared {len(feature_names)} features, {len(X)} samples")
        
        # Split
        X_train, X_test, y_train, y_test = self.split_train_test(
            X, y, test_size=test_size, temporal_split=temporal_split
        )
        print(f"Train: {len(X_train)} samples, Test: {len(X_test)} samples")
        
        # Scale
        scaler = None
        if scale:
            X_train, X_test, scaler = self.scale_features(X_train, X_test)
            print("Features scaled using StandardScaler")
            
        # Balance
        if balance:
            X_train, y_train = self.balance_dataset(X_train, y_train)
            print(f"Dataset balanced: Train now has {len(X_train)} samples")
            
        return {
            "X_train": X_train,
            "X_test": X_test,
            "y_train": y_train,
            "y_test": y_test,
            "feature_names": feature_names,
            "scaler": scaler,
            "validation_results": validation,
        }


def main():
    """Example usage."""
    preparator = DatasetPreparator()
    
    try:
        result = preparator.prepare_for_training(
            test_size=0.2,
            scale=True,
            balance=False,
            temporal_split=True
        )
        
        print("\n=== Dataset Preparation Complete ===")
        print(f"Feature names: {result['feature_names']}")
        print(f"Train shape: {result['X_train'].shape}")
        print(f"Test shape: {result['X_test'].shape}")
        print(f"Train labels: {np.bincount(result['y_train'])}")
        print(f"Test labels: {np.bincount(result['y_test'])}")
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()

