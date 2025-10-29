# XSS Detection ML/DL Model

This repository contains a machine learning model for detecting Cross-Site Scripting (XSS) attacks in HTTP responses.

## Model Overview

The model uses deep learning techniques (LSTM or CNN) to analyze HTTP responses and classify them as either malicious (containing XSS) or benign. It combines text analysis of payloads with numerical features extracted from the HTTP request and response.

## Requirements

- Python 3.9+
- PyTorch 1.9+
- NumPy
- Pandas
- Scikit-learn
- Matplotlib (for evaluation)
- Seaborn (for evaluation)

Install dependencies:

```bash
pip install torch numpy pandas scikit-learn matplotlib seaborn
```

## Directory Structure

```
projects/xss_detection/
├─ data/                      # Dataset files
├─ ml/                        # ML code
│  ├─ dataset.py              # Dataset preparation
│  ├─ models.py               # Model definitions
│  ├─ train.py                # Training pipeline
│  ├─ evaluate.py             # Evaluation script
│  ├─ tune.py                 # Hyperparameter tuning
│  ├─ utils.py                # Utilities
│  ├─ infer.py                # Inference script
│  └─ README.md               # This file
├─ models/                    # Saved models
│  ├─ best_model_<timestamp>.pt
│  ├─ tokenizer.json
│  └─ feature_scaler.pkl
└─ experiments/               # Experiment logs
   └─ run_<timestamp>/
      ├─ metrics.json
      ├─ config_used.json
      └─ logs/
```

## Usage

### Training a Model

To train a model with default parameters:

```bash
python ml/train.py
```

To train with a custom configuration:

```bash
python ml/train.py --config path/to/config.json
```

### Hyperparameter Tuning

To perform hyperparameter tuning:

```bash
python ml/tune.py --method random --n_trials 20
```

Options for `--method` are `grid` or `random`.

### Evaluation

To evaluate a trained model:

```bash
python ml/evaluate.py --model_timestamp <timestamp>
```

If no timestamp is provided, the latest model will be used.

### Inference

To use the model for inference, import the `XSSDetector` class:

```python
from ml.infer import XSSDetector

# Initialize detector (loads latest model by default)
detector = XSSDetector.get()

# Example request and response
request_data = {
    'method': 'GET',
    'payload': '<script>alert(1)</script>'
}

response_data = {
    'status_code': 200,
    'body': '<html><body><script>alert(1)</script></body></html>',
    'content_length': 52
}

# Make prediction
result = detector.predict(request_data, response_data)
print(f"Is malicious: {result['is_malicious']}")
print(f"Probability: {result['probability']:.4f}")
print(f"Inference time: {result['inference_time_ms']:.2f} ms")
```

## Model Performance

The model is evaluated on the following metrics:
- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC
- PR-AUC

Detailed evaluation reports can be found in the `experiments/run_<timestamp>/` directory after training.

## Safety Notes

- This model should only be used on data collected from lab/test instances or with explicit permission.
- Do not deploy to monitor or block traffic on production without human review and safety checks.
- The model may produce false positives or false negatives. Always verify results manually for critical applications.