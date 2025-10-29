# XSS Detection Model Training Notes

## Overview
This document provides details about the training process for the XSS detection machine learning models. The models are designed to classify HTTP responses as either malicious (containing XSS attempts) or benign based on various features extracted from the responses.

## Data Preparation

### Dataset
- Source: `projects/xss_detection/data/xss_response_dataset.csv`
- Features used:
  - `payload`: The XSS payload string
  - `method`: HTTP method (GET, POST)
  - `response_time`: Time taken for the response
  - `status_group`: HTTP status code group
  - `html_content_length`: Length of HTML content
  - `reflected_payload_present`: Whether the payload is reflected in the response
  - `is_malicious`: Target variable (1 for malicious, 0 for benign)

### Preprocessing
- Character-level tokenization for payload text
- Normalization of numerical features (response_time, html_content_length)
- One-hot encoding for categorical features (method)
- Additional engineered features:
  - Presence of `<script>` tags
  - Presence of `onerror=` attribute
  - Presence of `javascript:` protocol

### Data Splitting
- Train: 70%
- Validation: 15%
- Test: 15%
- Stratified by `is_malicious` to maintain class distribution

## Model Architecture

### LSTM Classifier
- Embedding layer for character-level tokens
- Bidirectional LSTM layer
- Global max pooling
- Concatenation with numerical features
- Fully connected layers with dropout
- Binary classification output

### CNN Classifier
- Embedding layer for character-level tokens
- Multiple parallel 1D convolutional layers with different kernel sizes (3, 5, 7)
- Global max pooling for each convolutional output
- Concatenation of pooled features and numerical features
- Fully connected layers with dropout
- Binary classification output

### Hybrid Model
- Combines both LSTM and CNN architectures
- Shared embedding layer
- Parallel LSTM and CNN branches
- Concatenation of LSTM and CNN features with numerical features
- Fully connected layers with dropout
- Binary classification output

## Training Process

### Hyperparameters
- Embedding dimension: [64, 128, 256]
- Hidden dimension: [64, 128, 256]
- Dropout rate: [0.1, 0.3, 0.5]
- Learning rate: [1e-4, 5e-4, 1e-3]
- Batch size: [32, 64, 128]
- Optimizer: Adam
- Loss function: Binary Cross-Entropy with Logits
- Early stopping patience: 5 epochs

### Training Approach
- Grid search or random search for hyperparameter tuning
- Early stopping based on validation F1 score
- Model checkpointing to save the best model
- Training history logging for analysis

## Evaluation Metrics
- Accuracy: Overall correctness of predictions
- Precision: Proportion of true positives among positive predictions
- Recall: Proportion of true positives identified
- F1 Score: Harmonic mean of precision and recall
- ROC-AUC: Area under the ROC curve
- PR-AUC: Area under the precision-recall curve

## Results and Analysis

### Performance Comparison
| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
|-------|----------|-----------|--------|----------|---------|
| LSTM  | TBD      | TBD       | TBD    | TBD      | TBD     |
| CNN   | TBD      | TBD       | TBD    | TBD      | TBD     |
| Hybrid| TBD      | TBD       | TBD    | TBD      | TBD     |

### Error Analysis
- Common false positives: TBD
- Common false negatives: TBD
- Performance by injection point: TBD

## Reproducibility
- Random seed set to 42
- Configuration files saved with each experiment
- Dataset version tracked
- Environment dependencies documented

## Future Improvements
- Experiment with more complex architectures (e.g., Transformers)
- Incorporate more domain-specific features
- Collect more diverse training data
- Implement active learning for continuous model improvement
- Explore ensemble methods for better performance

## Usage Instructions
To train a model with default parameters:
```
python train.py --data /path/to/xss_response_dataset.csv --output /path/to/output_directory
```

To tune hyperparameters:
```
python tune.py --data /path/to/xss_response_dataset.csv --output /path/to/output_directory --search grid
```

To evaluate a trained model:
```
python evaluate.py --model /path/to/model --data /path/to/xss_response_dataset.csv --output /path/to/output_directory
```

To make predictions with a trained model:
```
python infer.py --model /path/to/model --payload "<script>alert(1)</script>"
```