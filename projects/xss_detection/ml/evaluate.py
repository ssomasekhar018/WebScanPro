"""
Evaluation script for XSS detection models
"""
import os
import json
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, 
    roc_auc_score, precision_recall_curve, roc_curve, 
    confusion_matrix, classification_report
)
import torch

from ml.dataset import prepare_dataset, get_dataloaders
from ml.models import LSTMClassifier, CNNClassifier
from ml.utils import load_model, CharacterTokenizer

def evaluate_model(model_timestamp=None):
    """Evaluate model and generate reports"""
    # Load model, tokenizer and config
    if model_timestamp:
        model_class_map = {
            'lstm': LSTMClassifier,
            'cnn': CNNClassifier
        }
        
        # Load config first to determine model class
        config_path = os.path.join(
            'projects', 'xss_detection', 'models', 
            f'best_model_{model_timestamp}_config.json'
        )
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        model_class = model_class_map[config['model_type']]
        model, tokenizer, config = load_model(model_class, model_timestamp)
    else:
        # Find latest model
        model_dir = os.path.join('projects', 'xss_detection', 'models')
        model_files = [f for f in os.listdir(model_dir) if f.startswith('best_model_') and f.endswith('.pt')]
        
        if not model_files:
            raise FileNotFoundError("No model files found")
            
        # Sort by timestamp
        model_files.sort(reverse=True)
        model_timestamp = model_files[0].split('_')[1].split('.')[0]
        
        # Load config to determine model class
        config_path = os.path.join(
            model_dir, f'best_model_{model_timestamp}_config.json'
        )
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        model_class = LSTMClassifier if config['model_type'] == 'lstm' else CNNClassifier
        model, tokenizer, config = load_model(model_class, model_timestamp)
    
    print(f"Loaded model from timestamp: {model_timestamp}")
    print(f"Model type: {config['model_type']}")
    
    # Check for GPU
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = model.to(device)
    
    # Prepare dataset
    data_path = os.path.join('projects', 'xss_detection', 'data', 'xss_response_dataset.csv')
    splits, df = prepare_dataset(data_path)
    
    # Create dataloaders
    dataloaders = get_dataloaders(
        splits, 
        tokenizer, 
        max_length=config['max_length'],
        batch_size=32
    )
    
    # Evaluate on test set
    model.eval()
    test_preds = []
    test_probs = []
    test_labels = []
    
    with torch.no_grad():
        for batch in dataloaders['test']:
            # Get batch data
            input_ids = batch[0]['input_ids'].to(device)
            attention_mask = batch[0]['attention_mask'].to(device)
            numerical_features = batch[0]['numerical_features'].to(device)
            labels = batch[1].to(device)
            
            # Forward pass
            outputs = model(input_ids, attention_mask, numerical_features)
            
            # Store predictions and labels
            test_probs.extend(outputs.detach().cpu().numpy())
            test_preds.extend(outputs.detach().cpu().numpy() > 0.5)
            test_labels.extend(labels.detach().cpu().numpy())
    
    # Calculate metrics
    accuracy = accuracy_score(test_labels, test_preds)
    precision = precision_score(test_labels, test_preds)
    recall = recall_score(test_labels, test_preds)
    f1 = f1_score(test_labels, test_preds)
    auc = roc_auc_score(test_labels, test_preds)
    
    # Print metrics
    print("\nTest Set Metrics:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"ROC AUC: {auc:.4f}")
    
    # Generate confusion matrix
    cm = confusion_matrix(test_labels, test_preds)
    
    # Create experiment directory
    exp_dir = os.path.join('projects', 'xss_detection', 'experiments', f'evaluation_{model_timestamp}')
    os.makedirs(exp_dir, exist_ok=True)
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, 'confusion_matrix.png'))
    
    # Plot ROC curve
    fpr, tpr, _ = roc_curve(test_labels, test_probs)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {auc:.4f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, 'roc_curve.png'))
    
    # Plot Precision-Recall curve
    precision_curve, recall_curve, _ = precision_recall_curve(test_labels, test_probs)
    plt.figure(figsize=(8, 6))
    plt.plot(recall_curve, precision_curve, label=f'PR Curve')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, 'pr_curve.png'))
    
    # Generate classification report
    report = classification_report(test_labels, test_preds, target_names=['Benign', 'Malicious'])
    
    # Save metrics to JSON
    metrics = {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'auc': float(auc),
        'confusion_matrix': cm.tolist()
    }
    
    with open(os.path.join(exp_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Generate error analysis
    test_df = pd.DataFrame({
        'actual': test_labels,
        'predicted': test_preds,
        'probability': test_probs
    })
    
    # Get indices of false positives and false negatives
    fp_indices = np.where((test_df['actual'] == 0) & (test_df['predicted'] == 1))[0]
    fn_indices = np.where((test_df['actual'] == 1) & (test_df['predicted'] == 0))[0]
    
    # Get original payloads for error analysis
    test_idx = splits['test']['payloads'].index
    
    fp_examples = []
    for idx in fp_indices[:5]:  # Limit to 5 examples
        original_idx = test_idx[idx]
        fp_examples.append({
            'payload': df.iloc[original_idx]['payload'],
            'probability': float(test_df.iloc[idx]['probability']),
            'url': df.iloc[original_idx]['url'],
            'method': df.iloc[original_idx]['method']
        })
    
    fn_examples = []
    for idx in fn_indices[:5]:  # Limit to 5 examples
        original_idx = test_idx[idx]
        fn_examples.append({
            'payload': df.iloc[original_idx]['payload'],
            'probability': float(test_df.iloc[idx]['probability']),
            'url': df.iloc[original_idx]['url'],
            'method': df.iloc[original_idx]['method']
        })
    
    # Save error analysis
    error_analysis = {
        'false_positives': fp_examples,
        'false_negatives': fn_examples
    }
    
    with open(os.path.join(exp_dir, 'error_analysis.json'), 'w') as f:
        json.dump(error_analysis, f, indent=2)
    
    # Generate evaluation report markdown
    report_md = f"""# XSS Detection Model Evaluation Report

## Model Information
- **Model Type**: {config['model_type'].upper()}
- **Timestamp**: {model_timestamp}
- **Embedding Dimension**: {config['model_params']['embedding_dim']}
- **Hidden Size**: {config['model_params']['hidden_size']}

## Performance Metrics
- **Accuracy**: {accuracy:.4f}
- **Precision**: {precision:.4f}
- **Recall**: {recall:.4f}
- **F1 Score**: {f1:.4f}
- **ROC AUC**: {auc:.4f}

## Confusion Matrix
![Confusion Matrix](confusion_matrix.png)

## ROC Curve
![ROC Curve](roc_curve.png)

## Precision-Recall Curve
![PR Curve](pr_curve.png)

## Classification Report
```
{report}
```

## Error Analysis

### False Positives (Benign classified as Malicious)
{len(fp_indices)} instances ({len(fp_indices)/len(test_labels)*100:.2f}% of test set)

Examples:
{json.dumps(fp_examples, indent=2)}

### False Negatives (Malicious classified as Benign)
{len(fn_indices)} instances ({len(fn_indices)/len(test_labels)*100:.2f}% of test set)

Examples:
{json.dumps(fn_examples, indent=2)}

## Runtime Performance
- Average inference time per sample: TBD ms

## Conclusion
The model achieves {'good' if f1 >= 0.8 else 'moderate'} performance with an F1 score of {f1:.4f}.
{'The high recall of ' + str(recall) + ' indicates the model is effective at identifying malicious payloads.' if recall >= 0.85 else 'Further improvements could focus on increasing recall to better detect malicious payloads.'}
"""
    
    # Save evaluation report
    with open(os.path.join('projects', 'xss_detection', 'docs', 'evaluation_report.md'), 'w') as f:
        f.write(report_md)
    
    print(f"\nEvaluation report saved to projects/xss_detection/docs/evaluation_report.md")
    print(f"Evaluation artifacts saved to {exp_dir}")
    
    return metrics

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Evaluate XSS detection model')
    parser.add_argument('--timestamp', type=str, help='Model timestamp to evaluate')
    args = parser.parse_args()
    
    evaluate_model(args.timestamp)