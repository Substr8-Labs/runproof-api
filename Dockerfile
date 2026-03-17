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

# Create data directory
RUN mkdir -p /app/data

EXPOSE 8097

ENV PORT=8097
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}
