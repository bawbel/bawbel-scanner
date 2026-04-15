# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Bawbel Scanner" \
      org.opencontainers.image.description="Agentic AI component security scanner" \
      org.opencontainers.image.url="https://bawbel.io" \
      org.opencontainers.image.source="https://github.com/bawbel/bawbel-scanner" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy scanner source
COPY scanner/ ./scanner/
COPY cli.py .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash bawbel && \
    chown -R bawbel:bawbel /app

USER bawbel

# Mount point for files to scan
VOLUME ["/scan"]

# Default command — show help
ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
