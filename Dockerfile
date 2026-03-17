FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    pydantic \
    cryptography \
    httpx

# Copy application
COPY main.py .
COPY data/ ./data/

# Create data directory if not exists
RUN mkdir -p /app/data

EXPOSE 8097

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8097"]
