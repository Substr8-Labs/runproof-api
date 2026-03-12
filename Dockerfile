FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Install dependencies
RUN pip install --no-cache-dir -e .

ENV PORT=8765
EXPOSE $PORT

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=5 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

CMD uvicorn src.runproof_api.app:app --host 0.0.0.0 --port ${PORT}
