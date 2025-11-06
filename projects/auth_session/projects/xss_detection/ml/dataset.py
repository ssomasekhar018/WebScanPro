"""
Dataset and preprocessing utilities for XSS detection
"""
import os
import pandas as pd
import numpy as np
import pickle
import re
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import torch
from torch.utils.data import Dataset, DataLoader

class XSSDataset(Dataset):
    """Dataset class for XSS detection"""
    
    def __init__(self, features, labels):
        self.features = features
        self.labels = labels
        
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        # Return features as a dictionary and labels
        return {
            'input_ids': self.features['input_ids'][idx],
            'attention_mask': self.features['attention_mask'][idx],
            'numerical_features': self.features['numerical_features'][idx]
        }, self.labels[idx]

def clean_html(text):
    """Clean and normalize HTML/JS content"""
    if not isinstance(text, str):
        return ""
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Remove PII tokens (simplified example - extend as needed)
    text = re.sub(r'user_token=[a-zA-Z0-9]+', 'user_token=REDACTED', text)
    
    return text.strip()

def extract_features(df):
    """Extract features from the dataset"""
    # Basic features
    features = {
        'html_content_length': df['html_content_length'].values,
        'reflected_payload_present': df['reflected_payload_present'].values,
        'status_group': df['status_group'].apply(lambda x: int(x.split('x')[0])).values
    }
    
    # Add regex-based flags
    df['has_script_tag'] = df['payload'].apply(lambda x: 1 if '<script>' in str(x).lower() else 0)
    df['has_onerror'] = df['payload'].apply(lambda x: 1 if 'onerror' in str(x).lower() else 0)
    df['has_javascript'] = df['payload'].apply(lambda x: 1 if 'javascript:' in str(x).lower() else 0)
    
    features['has_script_tag'] = df['has_script_tag'].values
    features['has_onerror'] = df['has_onerror'].values
    features['has_javascript'] = df['has_javascript'].values
    
    return features

def prepare_dataset(data_path, test_size=0.2, val_size=0.1, random_state=42):
    """Prepare dataset for training, validation and testing"""
    # Load dataset
    df = pd.read_csv(data_path)
    
    # Check if dataset is empty
    if len(df) == 0:
        raise ValueError("Dataset is empty")
    
    print(f"Loaded dataset with {len(df)} samples")
    print(f"Class distribution: {df['is_malicious'].value_counts().to_dict()}")
    
    # Clean payloads
    df['cleaned_payload'] = df['payload'].apply(clean_html)
    
    # Extract features
    features = extract_features(df)
    
    # Get labels
    labels = df['is_malicious'].values
    
    # Special case for very small datasets
    if len(df) < 20:
        print("Small dataset detected, using manual split instead of stratified split")
        # Get indices for each class
        class_0_idx = np.where(labels == 0)[0]
        class_1_idx = np.where(labels == 1)[0]
        
        # Shuffle indices
        np.random.seed(random_state)
        np.random.shuffle(class_0_idx)
        np.random.shuffle(class_1_idx)
        
        # Split each class
        n0, n1 = len(class_0_idx), len(class_1_idx)
        
        # Calculate split sizes (ensure at least 1 sample per class in each split)
        n0_test = max(1, int(n0 * test_size))
        n1_test = max(1, int(n1 * test_size))
        
        n0_val = max(1, int((n0 - n0_test) * val_size / (1 - test_size)))
        n1_val = max(1, int((n1 - n1_test) * val_size / (1 - test_size)))
        
        # Ensure we have enough samples left for training
        n0_val = min(n0_val, n0 - n0_test - 1)
        n1_val = min(n1_val, n1 - n1_test - 1)
        
        # Create splits
        test_idx = np.concatenate([class_0_idx[:n0_test], class_1_idx[:n1_test]])
        val_idx = np.concatenate([class_0_idx[n0_test:n0_test+n0_val], class_1_idx[n1_test:n1_test+n1_val]])
        train_idx = np.concatenate([class_0_idx[n0_test+n0_val:], class_1_idx[n1_test+n1_val:]])
        
        # Shuffle the indices
        np.random.shuffle(train_idx)
        np.random.shuffle(val_idx)
        np.random.shuffle(test_idx)
    else:
        # For larger datasets, use stratified split
        # Split dataset
        train_idx, test_idx = train_test_split(
            np.arange(len(labels)), 
            test_size=test_size, 
            random_state=random_state, 
            stratify=labels
        )
        
        train_idx, val_idx = train_test_split(
            train_idx, 
            test_size=val_size/(1-test_size),
            random_state=random_state, 
            stratify=labels[train_idx]
        )
    
    # Ensure we have enough samples in each split
    print(f"Dataset split sizes: Train={len(train_idx)}, Val={len(val_idx)}, Test={len(test_idx)}")
    print(f"Class distribution: Train={np.sum(labels[train_idx])}/{len(train_idx)}, Val={np.sum(labels[val_idx])}/{len(val_idx)}, Test={np.sum(labels[test_idx])}/{len(test_idx)}")
    
    # Create dataset splits
    splits = {
        'train': {
            'payloads': df['cleaned_payload'].values[train_idx],
            'features': {k: v[train_idx] for k, v in features.items()},
            'labels': labels[train_idx]
        },
        'val': {
            'payloads': df['cleaned_payload'].values[val_idx],
            'features': {k: v[val_idx] for k, v in features.items()},
            'labels': labels[val_idx]
        },
        'test': {
            'payloads': df['cleaned_payload'].values[test_idx],
            'features': {k: v[test_idx] for k, v in features.items()},
            'labels': labels[test_idx]
        }
    }
    
    return splits, df

def get_dataloaders(splits, tokenizer, max_length=128, batch_size=32):
    """Create PyTorch DataLoaders for each split"""
    dataloaders = {}
    
    for split_name, split_data in splits.items():
        # Tokenize payloads
        encoded_inputs = tokenizer(
            split_data['payloads'].tolist(),
            padding='max_length',
            truncation=True,
            max_length=max_length,
            return_tensors='pt'
        )
        
        # Prepare numerical features
        numerical_features = np.stack([
            split_data['features']['html_content_length'],
            split_data['features']['reflected_payload_present'],
            split_data['features']['status_group'],
            split_data['features']['has_script_tag'],
            split_data['features']['has_onerror'],
            split_data['features']['has_javascript']
        ], axis=1).astype(np.float32)
        
        # Scale numerical features
        # Get absolute path for models directory
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(base_dir, 'models')
        os.makedirs(models_dir, exist_ok=True)
        scaler_path = os.path.join(models_dir, 'feature_scaler.pkl')
        
        if split_name == 'train':
            scaler = StandardScaler()
            numerical_features = scaler.fit_transform(numerical_features)
            # Save scaler for inference
            with open(scaler_path, 'wb') as f:
                pickle.dump(scaler, f)
        else:
            # Load scaler for validation and test
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            numerical_features = scaler.transform(numerical_features)
        
        # Create dataset
        features = {
            'input_ids': encoded_inputs['input_ids'],
            'attention_mask': encoded_inputs['attention_mask'],
            'numerical_features': torch.tensor(numerical_features, dtype=torch.float32)
        }
        
        dataset = XSSDataset(features, torch.tensor(split_data['labels'], dtype=torch.float32))
        
        # Create dataloader
        dataloaders[split_name] = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=(split_name == 'train')
        )
    
    return dataloaders

if __name__ == "__main__":
    # Test dataset preparation
    data_path = os.path.join('projects', 'xss_detection', 'data', 'xss_response_dataset.csv')
    splits, df = prepare_dataset(data_path)
    print(f"Train samples: {len(splits['train']['labels'])}")
    print(f"Val samples: {len(splits['val']['labels'])}")
    print(f"Test samples: {len(splits['test']['labels'])}")