"""
XSS Detection Model Training
Implements training pipeline for XSS detection models
"""
import os
import json
import argparse
from datetime import datetime
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from ml.dataset import prepare_dataset, get_dataloaders
from ml.models import LSTMClassifier, CNNClassifier
from ml.utils import CharacterTokenizer, save_model

def set_seed(seed):
    """Set random seed for reproducibility"""
    torch.manual_seed(seed)
    np.random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

def train_model(config):
    """Train model with given configuration"""
    # Set random seed
    set_seed(config['random_seed'])
    
    # Set device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load dataset
    data_path = config['data_path']
    print(f"Loading dataset from: {data_path}")
    splits, df = prepare_dataset(
        data_path, 
        test_size=config['test_size'],
        val_size=config['val_size'],
        random_state=config['random_seed']
    )
    
    # Create tokenizer
    tokenizer = CharacterTokenizer(max_length=config['max_length'])
    
    # Create models directory if it doesn't exist
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_dir = os.path.join(base_dir, 'models')
    os.makedirs(models_dir, exist_ok=True)
    print(f"Saving models to: {models_dir}")
    
    # Save tokenizer
    tokenizer_path = os.path.join(models_dir, 'tokenizer.json')
    tokenizer.save(tokenizer_path)
    
    # Create dataloaders
    dataloaders = get_dataloaders(
        splits, 
        tokenizer, 
        max_length=config['max_length'],
        batch_size=config['batch_size']
    )
    
    # Create model
    if config['model_type'] == 'lstm':
        model = LSTMClassifier(
            vocab_size=len(tokenizer.vocab),
            embedding_dim=config['embedding_dim'],
            hidden_size=config['hidden_size'],
            num_layers=config['num_layers'],
            dropout=config['dropout']
        )
    elif config['model_type'] == 'cnn':
        model = CNNClassifier(
            vocab_size=len(tokenizer.vocab),
            embedding_dim=config['embedding_dim'],
            num_filters=config['hidden_size'],
            filter_sizes=config['filter_sizes'],
            dropout=config['dropout']
        )
    else:
        raise ValueError(f"Unknown model type: {config['model_type']}")
    
    model = model.to(device)
    
    # Define loss function and optimizer
    criterion = nn.BCELoss()
    optimizer = getattr(optim, config['optimizer'])(
        model.parameters(), 
        lr=config['learning_rate'],
        weight_decay=config['weight_decay']
    )
    
    # Training loop
    best_val_f1 = 0
    best_model_state = None
    patience_counter = 0
    
    metrics = {
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': [],
        'train_f1': [],
        'val_f1': [],
        'train_precision': [],
        'val_precision': [],
        'train_recall': [],
        'val_recall': [],
        'train_auc': [],
        'val_auc': []
    }
    
    print(f"Starting training for {config['epochs']} epochs")
    
    # Initialize best_model_state with initial model state to avoid None issues
    best_model_state = model.state_dict().copy()
    
    for epoch in range(config['epochs']):
        # Training phase
        model.train()
        train_loss = 0
        train_preds = []
        train_labels = []
        
        for batch in dataloaders['train']:
            # Get batch data
            features, labels = batch
            input_ids = features['input_ids'].to(device)
            attention_mask = features['attention_mask'].to(device)
            numerical_features = features['numerical_features'].to(device)
            labels = labels.to(device)
            
            # Forward pass
            optimizer.zero_grad()
            outputs = model(input_ids, attention_mask, numerical_features)
            
            # Calculate loss
            loss = criterion(outputs, labels.float())
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            # Store predictions and labels
            train_loss += loss.item()
            train_preds.extend(outputs.detach().cpu().numpy() > 0.5)
            train_labels.extend(labels.detach().cpu().numpy())
        
        # Calculate training metrics
        train_loss /= len(dataloaders['train'])
        train_acc = accuracy_score(train_labels, train_preds)
        train_precision = precision_score(train_labels, train_preds)
        train_recall = recall_score(train_labels, train_preds)
        train_f1 = f1_score(train_labels, train_preds)
        train_auc = roc_auc_score(train_labels, train_preds)
        
        # Validation phase
        model.eval()
        val_loss = 0
        val_preds = []
        val_labels = []
        
        with torch.no_grad():
            for batch in dataloaders['val']:
                # Get batch data
                features, labels = batch
                input_ids = features['input_ids'].to(device)
                attention_mask = features['attention_mask'].to(device)
                numerical_features = features['numerical_features'].to(device)
                labels = labels.to(device)
                
                # Forward pass
                outputs = model(input_ids, attention_mask, numerical_features)
                
                # Calculate loss
                loss = criterion(outputs, labels.float())
                
                # Store predictions and labels
                val_loss += loss.item()
                val_preds.extend(outputs.detach().cpu().numpy() > 0.5)
                val_labels.extend(labels.detach().cpu().numpy())
        
        # Calculate validation metrics
        val_loss /= len(dataloaders['val'])
        val_acc = accuracy_score(val_labels, val_preds)
        val_precision = precision_score(val_labels, val_preds)
        val_recall = recall_score(val_labels, val_preds)
        val_f1 = f1_score(val_labels, val_preds)
        val_auc = roc_auc_score(val_labels, val_preds)
        
        # Store metrics
        metrics['train_loss'].append(train_loss)
        metrics['val_loss'].append(val_loss)
        metrics['train_acc'].append(float(train_acc))
        metrics['val_acc'].append(float(val_acc))
        metrics['train_precision'].append(float(train_precision))
        metrics['val_precision'].append(float(val_precision))
        metrics['train_recall'].append(float(train_recall))
        metrics['val_recall'].append(float(val_recall))
        metrics['train_f1'].append(float(train_f1))
        metrics['val_f1'].append(float(val_f1))
        metrics['train_auc'].append(float(train_auc))
        metrics['val_auc'].append(float(val_auc))
        
        # Print metrics
        print(f"Epoch {epoch+1}/{config['epochs']} - "
              f"Train Loss: {train_loss:.4f}, "
              f"Val Loss: {val_loss:.4f}, "
              f"Train F1: {train_f1:.4f}, "
              f"Val F1: {val_f1:.4f}")
        
        # Check for improvement
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_model_state = model.state_dict().copy()
            patience_counter = 0
            print(f"New best model with validation F1: {best_val_f1:.4f}")
        else:
            patience_counter += 1
            print(f"No improvement for {patience_counter} epochs")
            
        # Early stopping
        if patience_counter >= config['patience']:
            print(f"Early stopping after {epoch+1} epochs")
            break
    
    # Load best model
    model.load_state_dict(best_model_state)
    
    # Test phase
    model.eval()
    test_preds = []
    test_labels = []
    test_probs = []
    
    with torch.no_grad():
        for batch in dataloaders['test']:
            # Get batch data
            features, labels = batch
            input_ids = features['input_ids'].to(device)
            attention_mask = features['attention_mask'].to(device)
            numerical_features = features['numerical_features'].to(device)
            labels = labels.to(device)
            
            # Forward pass
            outputs = model(input_ids, attention_mask, numerical_features)
            
            # Store predictions and labels
            test_probs.extend(outputs.detach().cpu().numpy())
            test_preds.extend(outputs.detach().cpu().numpy() > 0.5)
            test_labels.extend(labels.detach().cpu().numpy())
    
    # Calculate test metrics
    test_acc = accuracy_score(test_labels, test_preds)
    test_precision = precision_score(test_labels, test_preds)
    test_recall = recall_score(test_labels, test_preds)
    test_f1 = f1_score(test_labels, test_preds)
    test_auc = roc_auc_score(test_labels, test_preds)
    
    # Add test metrics to metrics dict
    metrics['test_acc'] = float(test_acc)
    metrics['test_precision'] = float(test_precision)
    metrics['test_recall'] = float(test_recall)
    metrics['test_f1'] = float(test_f1)
    metrics['test_auc'] = float(test_auc)
    
    print(f"Test Results - "
          f"Accuracy: {test_acc:.4f}, "
          f"Precision: {test_precision:.4f}, "
          f"Recall: {test_recall:.4f}, "
          f"F1: {test_f1:.4f}, "
          f"AUC: {test_auc:.4f}")
    
    # Save model
    model_params = {
        'vocab_size': len(tokenizer.vocab),
        'embedding_dim': config['embedding_dim'],
        'hidden_size': config['hidden_size'],
        'num_layers': config.get('num_layers', 2),
        'dropout': config['dropout'],
        'filter_sizes': config.get('filter_sizes', [3, 5, 7])
    }
    
    config_to_save = {
        'model_type': config['model_type'],
        'model_params': model_params,
        'max_length': config['max_length']
    }
    
    timestamp = save_model(model, tokenizer, config_to_save, metrics)
    
    return model, tokenizer, metrics, timestamp

def get_default_config():
    """Get default configuration"""
    # Use absolute path for data file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(current_dir)  # xss_detection directory
    data_path = os.path.join(project_dir, 'data', 'xss_response_dataset.csv')
    
    print(f"Looking for dataset at: {data_path}")
    
    return {
        'model_type': 'lstm',  # 'lstm' or 'cnn'
        'embedding_dim': 128,
        'hidden_size': 128,
        'num_layers': 2,
        'filter_sizes': [3, 5, 7],
        'dropout': 0.3,
        'batch_size': 32,
        'learning_rate': 1e-3,
        'weight_decay': 1e-5,
        'optimizer': 'Adam',
        'epochs': 20,
        'patience': 5,
        'max_length': 128,
        'test_size': 0.2,
        'val_size': 0.1,
        'random_seed': 42,
        'data_path': data_path
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train XSS detection model')
    parser.add_argument('--config', type=str, help='Path to config file')
    args = parser.parse_args()
    
    # Load config
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    else:
        config = get_default_config()
    
    # Train model
    model, tokenizer, metrics, timestamp = train_model(config)
    
    print(f"Training completed. Model saved with timestamp: {timestamp}")