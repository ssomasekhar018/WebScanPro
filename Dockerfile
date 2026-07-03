# ─────────────────────────────────────────────────────────────────────────────
# WebScan Pro — Dockerfile
# Multi-stage build for a lean production image
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build dependencies ───────────────────────────────────────────────
FROM python:3.10-slim AS builder

WORKDIR /app

# Install system dependencies needed to compile some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python requirements
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Production image ─────────────────────────────────────────────────
FROM python:3.10-slim AS runtime

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Runtime system libs (libgomp for sklearn/torch parallelism)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy project source
COPY . .

# Create output directories used at runtime
RUN mkdir -p outputs/scan_reports outputs/logs \
             projects/auth_session/logs \
             projects/auth_session/docs \
             projects/auth_session/ml/rag/vectorstore

# Streamlit config — disable telemetry, set port
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
ENV STREAMLIT_SERVER_HEADLESS=true

# HuggingFace cache inside container
ENV HF_HOME=/app/.cache/huggingface
ENV TRANSFORMERS_CACHE=/app/.cache/huggingface

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default: run the Streamlit dashboard
CMD ["streamlit", "run", "projects/webscan_pro/streamlit_app.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]
