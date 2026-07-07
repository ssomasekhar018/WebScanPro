<div align="center">

# 🛡️ WebScan Pro


**🔴 LIVE DEMO:** [WebScan Pro on Streamlit Cloud](https://webscanpro-kpnzzfhqrdkrjseu4qv6ng.streamlit.app/)



### AI-Powered Automated Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2%2B-EE4C2C?style=flat-square&logo=pytorch&logoColor=white)](https://pytorch.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15%2B-FF6F00?style=flat-square&logo=tensorflow&logoColor=white)](https://tensorflow.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

> **Infosys Springboard Internship 6.0** — A production-grade web security tool that combines Machine Learning, Deep Learning, and Retrieval-Augmented Generation (RAG) to detect, analyze, and explain web application vulnerabilities.

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Modules](#-modules) · [ML Models](#-machine-learning-models) · [Docker](#-docker-deployment) · [Contributing](#-contributing)

</div>

---

## 📖 Overview

**WebScan Pro** is a fully automated web vulnerability scanner built in Python that identifies critical security weaknesses across web applications. It goes beyond traditional rule-based scanners by integrating trained machine learning models for detection and a RAG-powered AI pipeline to generate context-aware remediation guidance aligned with OWASP standards.

### What It Detects

| Vulnerability | OWASP Category | Detection Method |
|---------------|---------------|-----------------|
| **SQL Injection (SQLi)** | A03:2021 – Injection | Random Forest classifier + pattern matching |
| **Cross-Site Scripting (XSS)** | A03:2021 – Injection | PyTorch Bi-LSTM + Attention / CNN |
| **Insecure Direct Object Reference (IDOR)** | A01:2021 – Broken Access Control | HTTP probe engine + Isolation Forest / Random Forest |
| **Anomalous Server Responses** | General | Isolation Forest anomaly detection |

### Why WebScan Pro?

- **ML-augmented** — Trained classifiers dramatically reduce false positives compared to keyword-only scanners
- **AI-explained** — Each finding is automatically explained using a RAG pipeline backed by a curated security knowledge base
- **Modular** — Each vulnerability type is its own self-contained sub-module with independent models and scripts
- **Production-ready** — Ships with a Streamlit dashboard, Docker Compose deployment, and JSON/CSV report exports

---

## ✨ Features

- 🔴 **XSS Detection** — Bidirectional LSTM with attention pooling trained on real XSS payloads
- 💉 **SQL Injection Detection** — Random Forest trained on HTTP request-response feature pairs
- 🔐 **IDOR Detection** — Rule-based HTTP probing + supervised Random Forest (F1=1.00 on test set)
- 🤖 **RAG AI Analysis** — LangChain + FAISS + `flan-t5-large` for OWASP-aligned explanations
- 🖥️ **Streamlit Dashboard** — GitHub Dark Mode UI with severity-coded finding cards
- ⚙️ **Scan Configuration** — Toggle scan types, switch ML vs Rule-Based mode, tune timeout/payloads
- 📊 **Scan History** — In-session history table with per-scan drill-down
- 📤 **Report Export** — One-click JSON and CSV download per scan
- 🐳 **Docker Support** — Multi-stage Dockerfile + Docker Compose for easy deployment
- 🔁 **Retrainable** — Full data pipeline + training scripts for all models

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WebScan Pro — System Overview                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Streamlit Dashboard  (port 8501)                 │  │
│  │  Sidebar Config → URL Input → Scan Button → Results Cards    │  │
│  └───────────────────────────┬──────────────────────────────────┘  │
│                              │                                      │
│            ┌─────────────────┼─────────────────┐                   │
│            ▼                 ▼                 ▼                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ XSS Scanner  │  │ SQLi Scanner │  │    IDOR Probe Engine     │ │
│  │              │  │              │  │                          │ │
│  │ Bi-LSTM/CNN  │  │Random Forest │  │ URL Pattern Detection   │ │
│  │ (PyTorch)    │  │(scikit-learn)│  │ Adjacent-ID HTTP Probe  │ │
│  │ + Rule-based │  │ + Rule-based │  │ PII Leak Detection      │ │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬────────────┘ │
│         └─────────────────┼────────────────────────┘              │
│                           │ Findings                              │
│                           ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                    RAG AI Pipeline                          │   │
│  │                                                            │   │
│  │  Query → FAISS Retriever → Prompt → flan-t5-large → Answer │   │
│  │  Embeddings: sentence-transformers/all-MiniLM-L6-v2        │   │
│  └────────────────────────────────────────────────────────────┘   │
│                           │                                       │
│                           ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │              Report: JSON / CSV / Dashboard                 │   │
│  └────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
project-root/
│
├── 📄 README.md                        ← You are here
├── 📄 requirements.txt                 ← Unified Python dependencies
├── 🐳 Dockerfile                       ← Multi-stage Docker build
├── 🐳 docker-compose.yml               ← Docker Compose service
├── 🔒 .env.example                     ← Environment variable template
├── 📄 .gitignore
│
├── projects/
│   │
│   ├── webscan_pro/                    ← 🎯 Main Dashboard App
│   │   ├── streamlit_app.py            ← Streamlit frontend (full pipeline)
│   │   └── README.md
│   │
│   ├── unified_scanner/                ← 🔗 XSS + SQLi Combined Scanner
│   │   ├── unified_scanner.py          ← Main scanner class (threaded)
│   │   ├── inference_xss.py            ← XSS model inference wrapper
│   │   ├── inference_sqli.py           ← SQLi model inference wrapper
│   │   ├── mock_models.py              ← Rule-based fallback models
│   │   ├── reporting.py                ← JSON/CSV report generation
│   │   ├── utils.py                    ← HTTP utilities, payload lists
│   │   └── config.py                   ← Model paths, thresholds
│   │
│   ├── auth_session/                   ← 🔐 IDOR Detection Module
│   │   ├── comprehensive_idor_scanner.py ← Multi-app IDOR scanner
│   │   ├── create_synthetic_idor_dataset.py ← Synthetic data generator
│   │   ├── feature_engineering_idor.py  ← 17-feature extractor
│   │   ├── train_eval.py               ← Model training script
│   │   ├── scan_dashboard.py           ← CLI analytics dashboard
│   │   ├── mock_server.py              ← Flask test server
│   │   ├── ml/
│   │   │   ├── idor_model.joblib       ← Best model (Random Forest alias)
│   │   │   ├── random_forest_idor.joblib
│   │   │   ├── isolation_forest_model.pkl
│   │   │   ├── autoencoder_model.h5
│   │   │   ├── preprocessing_pipeline.pkl
│   │   │   ├── feature_extractor.py
│   │   │   └── rag/
│   │   │       ├── rag_pipeline.py     ← LangChain RAG chain
│   │   │       ├── build_knowledge_base.py
│   │   │       └── vectorstore/        ← FAISS index files
│   │   ├── data/
│   │   │   ├── idor_dataset_synthetic.csv  ← 1200-sample training data
│   │   │   ├── idor_features.csv
│   │   │   └── login_session_dataset.csv
│   │   └── docs/
│   │       ├── model_evaluation_report_v2.md
│   │       └── IDOR_Assessment_Final_Summary.md
│   │
│   ├── xss_detection/                  ← ⚡ XSS Detection Module
│   │   ├── ml/
│   │   │   ├── models.py               ← LSTM + CNN architectures
│   │   │   ├── train.py                ← PyTorch training pipeline
│   │   │   ├── evaluate.py             ← Metrics & evaluation
│   │   │   ├── infer.py                ← Inference pipeline
│   │   │   ├── dataset.py              ← Data loading & splitting
│   │   │   ├── utils.py                ← CharacterTokenizer, model I/O
│   │   │   └── tune.py                 ← Hyperparameter tuning
│   │   ├── models/
│   │   │   ├── best_model_*.pt         ← Trained PyTorch checkpoint
│   │   │   ├── best_model_*_config.json
│   │   │   └── tokenizer.json
│   │   ├── scanner/
│   │   │   ├── scanner.py              ← Reflected & stored XSS scanner
│   │   │   └── core.py                 ← HTTP request helpers
│   │   └── data/
│   │       ├── xss_response_dataset.csv
│   │       ├── payloads_reflected.csv
│   │       └── payloads_stored.csv
│   │
│   ├── sql_injection/                  ← 💉 SQL Injection Module
│   │   ├── scripts/
│   │   │   ├── train_and_evaluate_models.py
│   │   │   ├── feature_engineering.py
│   │   │   └── integrate_with_scanner.py
│   │   ├── models/
│   │   │   ├── best_model.pkl          ← Trained Random Forest
│   │   │   ├── random_forest_model.pkl
│   │   │   ├── decision_tree_model.pkl
│   │   │   └── preprocessor.pkl
│   │   ├── data/
│   │   │   ├── feature_dataset.csv
│   │   │   └── raw_server_responses.csv
│   │   └── notebooks/
│   │       └── model_training_evaluation.ipynb
│   │
│   └── logs/                           ← Runtime scan logs
│
├── notebooks/                          ← Jupyter Notebooks (EDA & training)
│   ├── anomaly_detection.ipynb
│   ├── data_preprocessing.ipynb
│   ├── feature_engineering.ipynb
│   ├── model_training_evaluation.ipynb
│   └── server_response_collection.ipynb
│
├── scripts/                            ← Shared data pipeline scripts
│   ├── collect_responses.py            ← HTTP response collector (DVWA)
│   ├── extract_features.py             ← Feature extraction
│   ├── preprocess_data.py              ← Data cleaning
│   ├── detect_anomalies.py             ← Anomaly detection runner
│   └── evaluate_models.py              ← Cross-model evaluation
│
├── models/                             ← Root-level shared models
│   ├── best_model.pkl
│   ├── random_forest_model.pkl
│   ├── isolation_forest_model.pkl
│   └── oneclass_svm_model.pkl
│
├── data/                               ← Shared datasets
│   ├── raw_server_responses.csv
│   ├── feature_dataset.csv
│   ├── cleaned_dataset.csv
│   └── anomaly_detection_results.csv
│
├── scanner/                            ← Core scanner engine
│   ├── scanner.py
│   ├── ml_integration.py
│   └── cli.py
│
└── outputs/                            ← Scan reports & logs (gitignored)
    ├── scan_reports/
    └── logs/
```

---

## ⚙️ Prerequisites

Before you begin, ensure your system meets the following requirements:

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.10 or 3.11 | Python 3.13 is supported but TensorFlow may require 3.10 |
| **pip** | 23.0+ | Run `pip install --upgrade pip` |
| **Git** | Any | For cloning the repository |
| **Docker** | 24.0+ | Optional — only needed for containerized deployment |
| **Docker Compose** | 2.0+ | Bundled with Docker Desktop |
| **RAM** | 4 GB minimum | 8 GB recommended when loading all ML models |
| **Disk** | 3 GB free | For models, dependencies, and HuggingFace cache |
| **HuggingFace Token** | Optional | Only needed for RAG AI explanations |

> **GPU Note:** The XSS LSTM model supports CUDA but defaults to CPU. The app is fully functional on CPU-only machines.

---

## 🚀 Quick Start

### Step 1 — Clone the Repository

```bash
git clone <your-repo-url>
cd project-root
```

### Step 2 — Set Up Environment Variables

```bash
# Copy the template
cp .env.example .env
```

Open `.env` and fill in your values:

```env
# Required for RAG AI explanations (get yours at https://huggingface.co/settings/tokens)
HUGGINGFACEHUB_API_TOKEN=hf_your_token_here

# Optional: DVWA target URL for testing
DVWA_BASE_URL=http://localhost/dvwa
```

> **Note:** The RAG pipeline is optional. If the token is not set, WebScan Pro automatically falls back to built-in OWASP explanations for each finding.

### Step 3 — Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **For GPU (CUDA) users:** Replace the `torch` line in `requirements.txt` with your system's CUDA wheel URL from [pytorch.org](https://pytorch.org/get-started/locally/).

### Step 4 — Launch the Dashboard

```bash
streamlit run projects/webscan_pro/streamlit_app.py
```

Open your browser at **[http://localhost:8501](http://localhost:8501)**

---

## 🐳 Docker Deployment

Docker bundles the entire application and all dependencies into a single container — no local Python setup required.

### Build and Run

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env and set HUGGINGFACEHUB_API_TOKEN

# 2. Build the image and start the container
docker compose up -d

# 3. Confirm it is running
docker compose ps

# 4. Stream live logs
docker compose logs -f webscan_pro
```

Open your browser at **[http://localhost:8501](http://localhost:8501)**

### Useful Docker Commands

```bash
# Stop the application
docker compose down

# Rebuild after code changes
docker compose up -d --build

# Open a shell inside the container
docker exec -it webscan_pro bash

# Include DVWA test target (uncomment in docker-compose.yml first)
docker compose up -d dvwa
```

### Docker Architecture

The `Dockerfile` uses a **multi-stage build** to keep the runtime image lean:

```
Stage 1 (builder)    → Installs all Python dependencies
Stage 2 (runtime)    → Copies site-packages + source code only
```

Volumes defined in `docker-compose.yml`:

| Volume | Description |
|--------|-------------|
| `./outputs` | Scan reports persist across restarts |
| `./projects/auth_session/logs` | Training logs persist |
| `hf_cache` | HuggingFace model cache (avoids re-download) |

---

## 🖥️ Using the Dashboard

### Dashboard Page

1. **Enter a target URL** in the input field (e.g., `https://example.com/profile?id=42`)
2. **Select scan types** in the sidebar (XSS, SQL Injection, IDOR — all enabled by default)
3. **Choose mode:**
   - **ML Mode** — Uses trained PyTorch/scikit-learn models (requires models to load)
   - **Rule-Based Mode** — Uses pattern matching only (faster, no model dependency)
4. **Click Scan** — The 3-step pipeline runs:
   - Step 1: Payload injection for XSS and SQLi
   - Step 2: IDOR parameter probing
   - Step 3: RAG AI explanation generation
5. **Review findings** — Color-coded severity cards with confidence scores, payloads that triggered detections, and AI-generated remediation steps
6. **Export** — Download results as **JSON** (machine-readable) or **CSV** (spreadsheet)

### History Page

- View a summary table of all scans performed in the current session
- Click any scan ID to drill into its full findings
- Export individual scan results as JSON
- Clear session history with one click

### Sidebar Controls

| Control | Description |
|---------|-------------|
| XSS Detection toggle | Enable/disable XSS scanning |
| SQL Injection toggle | Enable/disable SQLi scanning |
| IDOR Detection toggle | Enable/disable IDOR scanning |
| Rule-Based Mode toggle | Bypass ML models and use pattern matching |
| Request Timeout slider | Per-request timeout (2–30 seconds) |
| Max Payloads slider | Number of payloads tested per vulnerability type (3–50) |

---

## 📦 Modules

### Module 1: XSS Detection (`projects/xss_detection/`)

Detects **Cross-Site Scripting** by injecting payloads into target URLs and classifying server responses.

**Data Collection (`scanner/scanner.py`):**
- Sends reflected and stored XSS payloads to target forms
- Auto-labels responses based on whether the payload appears unescaped in the HTML
- Saves a labeled dataset to `data/xss_response_dataset.csv`

**Model Architecture (`ml/models.py`):**

```
Option A — LSTMClassifier (default):
  Input chars → Embedding(vocab, 128) → Bi-LSTM(128, 2 layers)
  → Attention pooling → Concat(numerical_features) → FC → Sigmoid

Option B — CNNClassifier:
  Input chars → Embedding(vocab, 128)
  → Conv1D(128, k=3) + Conv1D(128, k=5) + Conv1D(128, k=7)
  → Global MaxPool → Concat(numerical_features) → FC → Sigmoid
```

**Training (`ml/train.py`):**
```bash
cd projects/xss_detection
python ml/train.py
# or with custom config:
python ml/train.py --config path/to/config.json
```

Training features: early stopping (patience=5), validation F1 checkpoint saving, full metrics tracking (Accuracy, Precision, Recall, F1, AUC-ROC).

**Inference** is handled by `projects/unified_scanner/inference_xss.py` which loads the `.pt` checkpoint and `tokenizer.json`.

---

### Module 2: SQL Injection Detection (`projects/sql_injection/`)

Detects **SQL Injection** by analyzing HTTP request-response feature pairs.

**Feature Engineering (`scripts/feature_engineering.py`):**
Extracts features from request-response pairs:
- `response_time` — slow responses may indicate time-based blind SQLi
- `html_content_length` — content length changes between safe and injected requests
- `error_flag` — presence of SQL error keywords in response
- `reflected_flag` — whether the payload appears in the response

**Models Trained:**
| Model | File | Notes |
|-------|------|-------|
| Random Forest | `models/best_model.pkl` | Best performing (~370KB) |
| Random Forest (v2) | `models/random_forest_model.pkl` | |
| Decision Tree | `models/decision_tree_model.pkl` | Interpretable baseline |

**Training:**
```bash
cd project-root
python projects/sql_injection/scripts/train_and_evaluate_models.py
```

**Inference** is handled by `projects/unified_scanner/inference_sqli.py`.

---

### Module 3: IDOR Detection (`projects/auth_session/`)

Detects **Insecure Direct Object References** — one of the most common but hardest-to-detect vulnerabilities.

**How It Works:**

The IDOR detection runs in two complementary layers:

**Layer 1 — Rule-Based Probe Engine** (in `streamlit_app.py`):
1. Detects object-reference parameters in the URL using regex patterns (e.g., `?id=42`, `/users/42`, `?uid=123`)
2. Sends HTTP requests with adjacent IDs (`id=41`, `id=43`, `id=1`, etc.)
3. Compares response size, status code, and content to detect unauthorized data access
4. Scans responses for PII patterns (email addresses, phone numbers, credit card patterns)

**Layer 2 — ML Detection** (`comprehensive_idor_scanner.py`):
Extracts 17 features from request-response pairs:

| Feature | Description |
|---------|-------------|
| `self_access` | Is the requester accessing their own resource? |
| `param_delta` | Numeric difference between requester ID and target ID |
| `param_is_numeric` | Is the ID parameter a pure integer? |
| `param_is_sequential` | Is the ID in a predictable low-integer range? |
| `sensitive_data_found` | Does the response contain PII patterns? |
| `status_is_200/403/404` | Granular HTTP status code signals |
| `response_length` | Response body size in bytes |
| `response_is_large` | Is the response > 500 chars? |
| `has_auth_header` | Authorization/Cookie header present? |
| `param_change_rate` | How many unique targets does this user access? |
| `path_depth` | Depth of the URL path |
| `is_get` / `is_post` | HTTP method type |

**Models:**
| Model | Type | Test F1 | Notes |
|-------|------|---------|-------|
| **Random Forest** | Supervised | **1.00** | Best model (`idor_model.joblib`) |
| Isolation Forest | Unsupervised | 0.38 | Useful for zero-shot new endpoints |
| Autoencoder (Keras) | Unsupervised DL | 0.00 | Needs further threshold tuning |

**Applications Tested:**
- DVWA (Damn Vulnerable Web Application)
- OWASP Juice Shop
- Custom Flask Mock Server (`mock_server.py`)

---

### Module 4: Unified Scanner (`projects/unified_scanner/`)

Combines XSS and SQLi scanning into a single **multi-threaded pipeline** with a clean CLI interface.

```bash
# Scan a single URL
python projects/unified_scanner/unified_scanner.py --url https://target.com

# Scan multiple URLs from file
python projects/unified_scanner/unified_scanner.py --url-list urls.txt

# With custom options
python projects/unified_scanner/unified_scanner.py \
  --url https://target.com \
  --threads 8 \
  --timeout 10 \
  --max-payloads 25 \
  --xss-threshold 0.75 \
  --sqli-threshold 0.70 \
  --output report.json
```

**Key design decisions:**
- Falls back to `mock_models.py` (rule-based) automatically if trained models fail to load
- Uses `ThreadPoolExecutor` for parallel scanning across multiple URLs
- Saves structured JSON + CSV reports via `VulnerabilityReporter`

---

### Module 5: RAG AI Pipeline (`projects/auth_session/ml/rag/`)

Provides **context-aware, OWASP-aligned explanations** for every detected vulnerability using Retrieval-Augmented Generation.

**Architecture:**
```
User query (e.g., "Explain XSS and how to fix it")
  │
  ▼
FAISS Vector Store  ←  Security knowledge base (built once)
  │  (retrieves k=5 most relevant documents)
  ▼
PromptTemplate  →  "Use the following context to answer..."
  │
  ▼
google/flan-t5-large  (via HuggingFace Endpoint)
  │
  ▼
Answer + Source citations
```

**Build the Knowledge Base** (one-time setup):
```bash
python projects/auth_session/ml/rag/build_knowledge_base.py
# Creates: projects/auth_session/ml/rag/vectorstore/
```

**Test the RAG Pipeline:**
```bash
python projects/auth_session/ml/rag/rag_pipeline.py
# Runs a test query: "What is IDOR?"
```

**Environment Variable Required:**
```bash
export HUGGINGFACEHUB_API_TOKEN=hf_your_token_here
```

> If the token is not set or the pipeline fails, WebScan Pro automatically uses static OWASP explanations as fallback.

---

## 🤖 Machine Learning Models

### Summary

| Model File | Location | Algorithm | Task | Test Performance |
|-----------|----------|-----------|------|-----------------|
| `best_model_20251029_132159.pt` | `xss_detection/models/` | Bi-LSTM + Attention | XSS Classification | Trained on DVWA dataset |
| `best_model.pkl` | `sql_injection/models/` | Random Forest | SQLi Classification | ~370KB |
| `random_forest_idor.joblib` | `auth_session/ml/` | Random Forest | IDOR Detection | F1=1.00, AUC=1.00 |
| `isolation_forest_model.pkl` | `auth_session/ml/` | Isolation Forest | IDOR Anomaly | F1=0.38, AUC=0.65 |
| `autoencoder_model.h5` | `auth_session/ml/` | Keras Autoencoder | IDOR Anomaly | Needs tuning |
| `idor_model.joblib` | `auth_session/ml/` | Random Forest | Best model alias | Used by scanner |

### IDOR Random Forest — Top Feature Importances

```
self_access            ████████████████████  33.0%
param_delta            ███████████████████   30.7%
sensitive_data_found   ████                   6.4%
status_code_cat        ████                   6.0%
response_length        ████                   5.9%
has_auth_header        ███                    5.6%
status_is_200          ███                    4.6%
```

---

## 🔁 Retraining Models

### Retrain IDOR Models (Recommended after adding new data)

```bash
# Step 1: Generate fresh synthetic training data
python projects/auth_session/create_synthetic_idor_dataset.py
# Output: projects/auth_session/data/idor_dataset_synthetic.csv (1200 rows)

# Step 2: Train all three IDOR models
python projects/auth_session/train_eval.py
# Outputs:
#   projects/auth_session/ml/random_forest_idor.joblib
#   projects/auth_session/ml/isolation_forest_model.pkl
#   projects/auth_session/ml/autoencoder_model.h5
#   projects/auth_session/ml/idor_model.joblib  (best model alias)
#   projects/auth_session/docs/model_evaluation_report_v2.md
```

### Retrain XSS Model

```bash
# Collect fresh XSS data from DVWA (requires DVWA running)
python projects/xss_detection/scanner/scanner.py

# Train LSTM or CNN model
cd projects/xss_detection
python ml/train.py
# or with CNN:
# Edit ml/train.py → set model_type = 'cnn'
```

### Retrain SQLi Model

```bash
# Collect responses from DVWA
python scripts/collect_responses.py

# Extract features
python scripts/extract_features.py

# Train and evaluate
python projects/sql_injection/scripts/train_and_evaluate_models.py
```

### Run Data Preprocessing Pipeline (all modules)

```bash
python scripts/collect_responses.py    # 1. Collect HTTP responses
python scripts/extract_features.py    # 2. Extract features
python scripts/preprocess_data.py     # 3. Clean & normalize
python scripts/detect_anomalies.py    # 4. Run anomaly detection
python scripts/evaluate_models.py     # 5. Evaluate all models
```

---

## 📊 Jupyter Notebooks

Exploratory analysis and model prototyping notebooks are in `notebooks/`:

| Notebook | Description |
|----------|-------------|
| `server_response_collection.ipynb` | HTTP response data collection from DVWA |
| `data_preprocessing.ipynb` | Data cleaning, normalization, EDA |
| `feature_engineering.ipynb` | Feature design and selection experiments |
| `feature_extraction.ipynb` | Feature extraction pipeline prototyping |
| `model_training_evaluation.ipynb` | Model training and metric visualization |
| `anomaly_detection.ipynb` | Anomaly detection experiments (IF, One-Class SVM) |

```bash
# Launch Jupyter
jupyter notebook notebooks/
```

---

## 🧪 Testing Against DVWA

DVWA (Damn Vulnerable Web Application) is the recommended target for testing WebScan Pro.

### Option 1: Docker (Easiest)

```bash
# Start DVWA
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa

# Access DVWA
# Open: http://localhost:8080
# Login: admin / password
# Click "Create / Reset Database"
# Set Security Level → Low
```

### Option 2: Uncomment in docker-compose.yml

```yaml
# Uncomment these lines in docker-compose.yml:
  dvwa:
    image: vulnerables/web-dvwa:latest
    ports:
      - "8080:80"
```

```bash
docker compose up -d dvwa
```

### Test URLs to Try in WebScan Pro

```
# SQL Injection test page
http://localhost:8080/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit

# XSS Reflected test page
http://localhost:8080/dvwa/vulnerabilities/xss_r/?name=test

# XSS Stored test page
http://localhost:8080/dvwa/vulnerabilities/xss_s/

# IDOR / Insecure File Upload
http://localhost:8080/dvwa/vulnerabilities/fi/?page=include.php
```

---

## 🌍 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HUGGINGFACEHUB_API_TOKEN` | For RAG | None | HuggingFace token for `flan-t5-large` LLM inference |
| `DVWA_BASE_URL` | Optional | `http://localhost/dvwa` | Target DVWA instance URL |
| `STREAMLIT_SERVER_PORT` | Optional | `8501` | Port for the Streamlit dashboard |

Create your `.env` file:
```bash
cp .env.example .env
```

---

## 🛠️ Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| **Language** | Python | 3.10+ |
| **Frontend** | Streamlit | 1.32+ |
| **ML Framework** | scikit-learn | 1.4+ |
| **Deep Learning** | PyTorch | 2.2+ |
| **Deep Learning** | TensorFlow / Keras | 2.15+ |
| **RAG Framework** | LangChain | 0.1+ |
| **Vector Store** | FAISS | 1.7+ |
| **Embeddings** | sentence-transformers | 2.5+ |
| **LLM** | google/flan-t5-large | via HuggingFace |
| **HTTP** | requests, BeautifulSoup | 2.31+, 4.12+ |
| **Data** | pandas, numpy | 2.1+, 1.26+ |
| **Visualization** | matplotlib, seaborn | 3.8+, 0.13+ |
| **Containerization** | Docker + Compose | 24.0+, 2.0+ |

---

## 📈 Performance Metrics

### IDOR Random Forest (Test Set — 180 samples)

| Metric | Score |
|--------|-------|
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1-Score | 1.0000 |
| AUC-ROC | 1.0000 |
| False Positive Rate | 0.0000 |
| False Negative Rate | 0.0000 |

> **Note:** The perfect score is on the synthetic dataset. Real-world performance will vary. The model learns strong discriminative signals from `self_access` and `param_delta` features.

### IDOR Isolation Forest

| Metric | Score |
|--------|-------|
| Accuracy | 0.5833 |
| F1-Score | 0.3802 |
| AUC-ROC | 0.6457 |

---

## 🔒 Security & Responsible Use

> **⚠️ Important:** WebScan Pro is designed for **authorized security testing only**.

- Only scan web applications you own or have **explicit written permission** to test
- Never run scans against production systems without a signed authorization agreement
- SQLi and XSS payloads used during scanning can cause unintended side effects on fragile systems
- Use DVWA, OWASP Juice Shop, or your own test environments for development and research

The tool is intended for:
- Security researchers and penetration testers
- Developers learning about web vulnerability patterns
- Students in cybersecurity and ML programs (e.g., Infosys Springboard)

---

## 📝 Known Limitations

| Limitation | Detail |
|-----------|--------|
| **IDOR model overfitting** | Perfect F1 on synthetic data; real-world accuracy will be lower |
| **Autoencoder IDOR** | Currently F1=0.00; threshold needs tuning with real data |
| **JavaScript rendering** | Scanner does not execute JavaScript (no Selenium integration yet) |
| **Authentication** | No built-in session/cookie handling for authenticated scans |
| **RAG availability** | Requires HuggingFace API token; offline mode uses static OWASP text |
| **Scanner is not stealthy** | No rate limiting or request randomization — easily detected by WAFs |

---

## 🗺️ Roadmap

- [ ] Authenticated scanning (session cookie injection)
- [ ] JavaScript rendering support (Selenium/Playwright integration)
- [ ] CSRF detection module
- [ ] SSRF detection module
- [ ] Burp Suite integration plugin
- [ ] Real-world IDOR dataset collection and model re-evaluation
- [ ] Autoencoder threshold auto-tuning
- [ ] PDF report generation
- [ ] REST API endpoint for programmatic scanning

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m "feat: describe your change"`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

### Code Style
- Follow PEP 8 for Python files
- Add docstrings to all public functions and classes
- Keep ML training scripts runnable as `__main__` with sensible defaults

---

## 📄 License

This project is developed as part of the **Infosys Springboard Internship 6.0** program.

---

## 👤 Author

**Infosys Springboard Intern**
- Project: WebScan Pro — AI-Powered Web Vulnerability Scanner
- Program: Infosys Springboard 6.0

---

<div align="center">

Built with 🔐 for the **Infosys Springboard Internship 6.0**

*WebScan Pro — Scan smarter. Fix faster.*

</div>
