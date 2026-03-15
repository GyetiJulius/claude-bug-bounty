# ============================================================================
# AppSec Multi-Agent Framework — Dockerfile
#
# Two-stage build:
#   1. tool-builder  — installs Go and compiles all security tools
#   2. runtime       — minimal Python image with app code + compiled tools
#
# Build:
#   docker build -t appsec-framework .
#
# Run (web UI on port 8000):
#   docker run -p 8000:8000 --env-file .env -v $(pwd)/output:/app/output appsec-framework
# ============================================================================

# ─── Stage 1: Build Go security tools ────────────────────────────────────
FROM golang:1.22-bookworm AS tool-builder

ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery + other security tools via go install
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest        2>&1 | tail -3
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest                   2>&1 | tail -3
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest               2>&1 | tail -3
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest                  2>&1 | tail -3
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest                                  2>&1 | tail -3
RUN go install -v github.com/tomnomnom/waybackurls@latest                               2>&1 | tail -3
RUN go install -v github.com/tomnomnom/assetfinder@latest                               2>&1 | tail -3

# ─── Stage 2: Python runtime ─────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="AppSec Multi-Agent Framework"
LABEL org.opencontainers.image.description="Defensive security scanning framework with web UI"

# System packages needed at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Go binaries from builder
COPY --from=tool-builder /go/bin/ /usr/local/bin/

# Update nuclei templates (best-effort; fails silently if no network)
RUN nuclei -update-templates -silent 2>/dev/null || true

# ─── Python setup ────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory with proper permissions
RUN mkdir -p /app/output && chmod 777 /app/output

# ─── Runtime configuration ───────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OUTPUT_DIR=/app/output

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000"]
