"""Tests for verify API."""

import pytest
from fastapi.testclient import TestClient

from verify_api import app


client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_stats():
    response = client.get("/stats")
    assert response.status_code == 200
    assert "stored_proofs" in response.json()


def test_verify_invalid_proof():
    response = client.post("/verify", json={"proof": {}})
    assert response.status_code == 400


def test_proof_not_found():
    response = client.get("/proof/nonexistent")
    assert response.status_code == 404
