# ═══════════════════════════════════════════════════════════════
# GOD_EYE — Multi-stage Dockerfile
# Stages: base → builder → production
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Base Python image ──────────────────────────────────
FROM python:3.11-slim-bookworm AS base

# Install system dependencies needed at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Playwright dependencies
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libexpat1 \
    libxcb1 \
    libxkbcommon0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libatspi2.0-0 \
    # WeasyPrint dependencies (PDF export)
    libpango1.0-0 \
    libharfbuzz0b \
    libffi-dev \
    libgdk-pixbuf2.0-0 \
    # Image processing
    libgl1 \
    libglib2.0-0 \
    # Network tools
    curl \
    wget \
    dnsutils \
    # Misc
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Set Python environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ── Stage 2: Builder (install deps) ─────────────────────────────
FROM base AS builder

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (for Docker layer caching)
COPY pyproject.toml ./
COPY README.md ./
COPY app ./app

# Install Python dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install core deps (excluding ML/GPU heavy ones by default)
RUN pip install --upgrade pip && \
    pip install -e ".[dev]" && \
    # Install Playwright browsers
    playwright install chromium firefox && \
    playwright install-deps chromium firefox

# Download spaCy model
RUN python -m spacy download en_core_web_sm || true

# ── Stage 3: Production ──────────────────────────────────────────
FROM base AS production

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /root/.cache/ms-playwright /root/.cache/ms-playwright

# Set PATH to use venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY app/ ./app/
COPY data/templates/ ./data/templates/
COPY config.yaml ./
COPY scripts/ ./scripts/

# Create data directories
RUN mkdir -p data/{requests,cache,logs,sessions,templates}

# Create non-root user for security
RUN groupadd -r god_eye && useradd -r -g god_eye god_eye && \
    chown -R god_eye:god_eye /app

# Use non-root user
USER god_eye

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command: start FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# ── Stage 4: Development ──────────────────────────────────────────
FROM production AS development

USER root

# Install dev tools
RUN pip install ipython pre-commit

# Mount source code (dev uses volumes instead of COPY)
WORKDIR /app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
