# verify-api

Backend API for RunProof verification UI.

## 4 Views

| View | Endpoint | Purpose |
|------|----------|---------|
| Summary | `GET /proof/{id}/summary` | Green tick page, status, IDs |
| Timeline | `GET /proof/{id}/timeline` | Ordered events, developer view |
| Lineage | `GET /proof/{id}/lineage` | Parent/child tree, delegations |
| Report | `GET /proof/{id}/report` | Audit checks, verification details |

## Quick Start

```bash
# Install
pip install -e .

# Run server
uvicorn verify_api:app --reload --port 8000

# Test
curl http://localhost:8000/health
```

## API Usage

```python
import httpx

# Verify a proof
response = httpx.post("http://localhost:8000/verify", json={"proof": proof_dict})
result = response.json()
print(result["valid"])  # True/False
print(result["proof_id"])

# Get all views
response = httpx.get(f"http://localhost:8000/proof/{proof_id}")
views = response.json()
print(views["summary"]["status"])
print(views["timeline"]["total_events"])
print(views["report"]["human_summary"])
```

## License

MIT
