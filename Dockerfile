# =============================================================================
# XtractR Dockerfile — Reproducible Forensic Build
# =============================================================================
# Produces a deterministic, minimal container for court-admissible analysis.
#
# Build:  docker build -t xtractr:latest .
# Test:   docker run --rm xtractr:latest make test
# Run:    docker run --rm -v /evidence:/evidence -v /output:/output \
#           xtractr:latest python xtractr.py /evidence /output/case_001
# =============================================================================

# --- Stage 1: Base ---
FROM python:3.13-slim AS base

# Deterministic environment (INV-002)
ENV PYTHONHASHSEED=0 \
    LC_ALL=C \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# System dependencies for SQLite and crypto
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    make \
    && rm -rf /var/lib/apt/lists/*

# --- Stage 2: Dependencies ---
FROM base AS deps

WORKDIR /app

# Install pinned dependencies first (layer caching)
COPY requirements-lock.txt ./
RUN pip install --no-cache-dir -r requirements-lock.txt

# --- Stage 3: Application ---
FROM deps AS app

# Copy application code
COPY core/ ./core/
COPY plugins/ ./plugins/
COPY tests/ ./tests/
COPY xtractr.py xtractr_verify.py Makefile ./

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash xtractr && \
    chown -R xtractr:xtractr /app

USER xtractr

# Health check: verify imports work
RUN python -c "from core.database import CaseDatabase; from core.plugin_engine import PluginEngine; print('OK')"

# Default: run tests
CMD ["make", "test"]
