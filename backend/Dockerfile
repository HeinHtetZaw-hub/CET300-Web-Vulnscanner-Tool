# ── Stage 1: build & install dependencies ────────────────────────────────────
FROM python:3.11-slim AS base

# System packages:
#   - libpango*, libffi-dev, libjpeg-dev, libopenjp2-7  → fpdf2 / WeasyPrint
#   - chromium, chromium-driver                          → Selenium DOM XSS module
#   - curl                                               → health-check / debugging
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libffi-dev \
        libjpeg-dev \
        libopenjp2-7 \
        chromium \
        chromium-driver \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps in a separate layer so Docker caches them between code changes
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create the data directory for SQLite persistence and ensure it's writable
RUN mkdir -p /app/data

EXPOSE 8000

# Lightweight health check using the /health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
