# RunProof API

Backend API for the RunProof Protocol — cryptographically verifiable receipts for AI agent execution.

## Protocol Layers

```
Layer 7: Agent Lifecycle    (always-on agents)
Layer 6: External Anchoring (blockchain/notary)
Layer 5: Policy Binding     (governance)
Layer 4: State Proofs       (transitions)
Layer 3: Proof Graphs       (DAG composition)
Layer 2: Signatures         (Ed25519 attestation)
Layer 1: Receipts           (atomic proofs)
```

## Quick Start

```bash
# Run locally
pip install fastapi uvicorn pydantic cryptography
uvicorn main:app --port 8097

# Run with Docker
docker build -t runproof-api .
docker run -p 8097:8097 runproof-api
```

## API Endpoints

### Run Lifecycle
- `POST /v1/run/start` — Start a new run
- `POST /v1/run/event` — Record event (auto-creates run)
- `POST /v1/run/end` — End run and generate proof
- `GET /v1/runproof/{run_id}` — Get proof
- `GET /v1/runproof/{run_id}/verify` — Verify proof

### Proof Graphs
- `POST /v1/proof-graph/link` — Link proofs
- `GET /v1/proof-graph/{root_id}` — Get graph
- `GET /v1/runproof/{run_id}/ancestry` — Get lineage
- `GET /v1/runproof/{run_id}/descendants` — Get children

### State Proofs
- `POST /v1/state-proof` — Record state transition
- `GET /v1/state-chain/{type}/verify` — Verify chain

### Policy Binding
- `POST /v1/policy-binding` — Bind policy to run
- `GET /v1/runproof/{run_id}/policies` — Get policies

### External Anchoring
- `POST /v1/anchor` — Submit for anchoring
- `POST /v1/anchor/{id}/confirm` — Confirm anchor
- `GET /v1/anchors/pending` — List pending

### Agent Lifecycle
- `POST /v1/agent/{id}/register` — Register agent
- `POST /v1/agent/{id}/heartbeat` — Record heartbeat
- `GET /v1/agents/active` — List active agents

## Testing

```bash
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```

## Documentation

Full docs at [docs.substr8labs.com](https://docs.substr8labs.com)

## License

MIT
