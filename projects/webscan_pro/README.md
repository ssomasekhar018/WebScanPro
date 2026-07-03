# 🛡️ WebScan Pro

An **AI-powered automated web vulnerability scanner** that detects XSS, SQL Injection, and IDOR vulnerabilities using machine learning models and rule-based heuristics, with RAG-powered explanations.

---

## ✨ Features

| Feature | Details |
|---------|---------|
| **XSS Detection** | PyTorch Bi-LSTM + Attention / CNN with rule-based fallback |
| **SQL Injection** | Random Forest classifier + pattern matching fallback |
| **IDOR Detection** | URL probe engine + Isolation Forest / Random Forest ML model |
| **AI Explanations** | LangChain RAG pipeline (FAISS + `flan-t5-large`) with OWASP references |
| **Scan History** | In-session history with detailed per-scan drill-down |
| **Export** | JSON and CSV report downloads per scan |
| **Mode Toggle** | Switch between ML Mode and Rule-Based Mode from the sidebar |

---

## 🚀 Quick Start

### Option 1: Run locally with Python

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) Set HuggingFace token for RAG pipeline
cp .env.example .env
# Edit .env and add your HUGGINGFACEHUB_API_TOKEN

# 3. Run the dashboard
streamlit run projects/webscan_pro/streamlit_app.py
```

Open → **http://localhost:8501**

### Option 2: Run with Docker

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env → set HUGGINGFACEHUB_API_TOKEN

# 2. Build and start
docker compose up -d

# 3. View logs
docker compose logs -f webscan_pro
```

Open → **http://localhost:8501**

---

## 🏗️ Architecture

```
WebScan Pro
├── Streamlit UI (streamlit_app.py)
│   ├── Sidebar: scan config, mode toggle, status
│   ├── Dashboard: URL input → scan → severity cards
│   ├── History: past scans table + detail view
│   └── About: tech stack overview
│
├── Scanner Engine
│   ├── UnifiedScanner (XSS + SQLi) — projects/unified_scanner/
│   │   ├── XSS: inference_xss.py → PyTorch LSTM/CNN model
│   │   ├── SQLi: inference_sqli.py → Random Forest model
│   │   └── Fallback: mock_models.py (pattern matching)
│   │
│   └── IDOR Probe Engine (built into streamlit_app.py)
│       ├── URL pattern detection (regex)
│       ├── Adjacent-ID probing (HTTP requests)
│       └── Personal data leak detection
│
└── RAG Pipeline — projects/auth_session/ml/rag/
    ├── FAISS vector store (pre-built security knowledge base)
    ├── Embeddings: sentence-transformers/all-MiniLM-L6-v2
    └── LLM: google/flan-t5-large (HuggingFace Endpoint)
```

---

## 🤖 ML Models

| Model | File | Task |
|-------|------|------|
| XSS LSTM | `xss_detection/models/best_model_*.pt` | XSS classification |
| SQLi RF | `sql_injection/models/best_model.pkl` | SQL Injection |
| IDOR RF | `auth_session/ml/random_forest_idor.joblib` | IDOR (supervised) |
| IDOR IF | `auth_session/ml/isolation_forest_model.pkl` | IDOR (unsupervised) |
| IDOR AE | `auth_session/ml/autoencoder_model.h5` | IDOR (deep anomaly) |

---

## 🔁 Retrain IDOR Model

```bash
# Step 1: Generate synthetic training data (1200 samples)
python projects/auth_session/create_synthetic_idor_dataset.py

# Step 2: Retrain all three IDOR models
python projects/auth_session/train_eval.py
```

Evaluation report is written to `projects/auth_session/docs/model_evaluation_report_v2.md`.

---

## 📁 Key Files

```
projects/webscan_pro/
├── streamlit_app.py         ← Main dashboard (this app)
└── README.md

projects/auth_session/
├── create_synthetic_idor_dataset.py  ← IDOR data generator
├── feature_engineering_idor.py       ← 17-feature IDOR extractor
├── train_eval.py                     ← IDOR model training
├── comprehensive_idor_scanner.py     ← IDOR scanner (DVWA/Juice Shop)
└── ml/rag/rag_pipeline.py            ← RAG pipeline

projects/unified_scanner/
├── unified_scanner.py       ← XSS + SQLi combined scanner
├── inference_xss.py         ← XSS model inference
├── inference_sqli.py        ← SQLi model inference
└── mock_models.py           ← Fallback pattern-matching models

projects/xss_detection/ml/
├── train.py                 ← PyTorch LSTM/CNN training
├── models.py                ← Model architectures
└── evaluate.py              ← Evaluation metrics

projects/sql_injection/
├── scripts/train_and_evaluate_models.py
└── models/best_model.pkl
```

---

## ⚙️ Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HUGGINGFACEHUB_API_TOKEN` | For RAG | HuggingFace API token for `flan-t5-large` |
| `DVWA_BASE_URL` | Optional | Override DVWA target URL (default: `http://localhost/dvwa`) |

---

## 🧪 Testing Against DVWA

1. Start DVWA: `docker run -p 8080:80 vulnerables/web-dvwa`
2. Login at `http://localhost:8080` (admin / password)
3. Set Security Level to **Low**
4. Paste a DVWA URL into WebScan Pro and click **Scan**
