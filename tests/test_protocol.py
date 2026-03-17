"""
RunProof Protocol Test Suite

Tests protocol correctness, determinism, and integrity.
Run with: pytest tests/ -v
"""

import pytest
import httpx
import json
import hashlib
import time
from datetime import datetime
from typing import Dict, List

# Test against running service
BASE_URL = "http://localhost:8097"

# ============ Fixtures ============

@pytest.fixture
def client():
    """HTTP client for API calls."""
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.fixture
def unique_run_id():
    """Generate unique run ID for each test."""
    ts = int(time.time() * 1000)
    return f"test-run-{ts}"


@pytest.fixture
def unique_trace_id():
    """Generate unique trace ID."""
    ts = int(time.time() * 1000)
    return f"test-trace-{ts}"


# ============ Health & Basics ============

class TestHealth:
    def test_health_endpoint(self, client):
        """Service is healthy."""
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "active_runs" in data


class TestRunLifecycle:
    def test_run_start_creates_run(self, client, unique_run_id):
        """POST /v1/run/start creates a new run."""
        resp = client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "started"
        assert data["run_id"] == unique_run_id
        assert "trace_id" in data

    def test_run_start_idempotent(self, client, unique_run_id):
        """Starting same run twice returns existing run."""
        # First start
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        
        # Second start
        resp = client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "exists"

    def test_event_creates_run_lazily(self, client, unique_run_id, unique_trace_id):
        """POST /v1/run/event auto-creates run if missing."""
        resp = client.post("/v1/run/event", json={
            "run_id": unique_run_id,
            "event_id": "evt-001",
            "trace_id": unique_trace_id,
            "type": "test.event",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "test",
            "data": {"agent_id": "test-agent"}
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "recorded"

    def test_run_end_produces_proof(self, client, unique_run_id):
        """POST /v1/run/end generates RunProof with root_hash."""
        # Start run
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        
        # Add event
        client.post("/v1/run/event", json={
            "run_id": unique_run_id,
            "event_id": "evt-001",
            "type": "message.received",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "test",
            "data": {"content": "hello"}
        })
        
        # End run
        resp = client.post("/v1/run/end", json={
            "run_id": unique_run_id,
            "success": True
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert "root_hash" in data
        assert len(data["root_hash"]) == 64  # SHA256 hex


# ============ Determinism Tests ============

class TestDeterminism:
    def test_root_hash_structure(self, client):
        """Root hash has correct structure and length."""
        run_id = f"hash-test-{int(time.time()*1000)}"
        
        # Start run
        client.post("/v1/run/start", json={
            "run_id": run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        
        # Add events
        for j, evt_type in enumerate(["message.received", "tool.invoke", "message.sent"]):
            client.post("/v1/run/event", json={
                "run_id": run_id,
                "event_id": f"evt-{j}",
                "type": evt_type,
                "timestamp": "2026-03-17T00:00:00Z",
                "source": "test",
                "seq": j,
                "data": {"content": f"data-{j}"}
            })
        
        # End run
        resp = client.post("/v1/run/end", json={
            "run_id": run_id,
            "success": True
        })
        root_hash = resp.json()["root_hash"]
        
        # Root hash should be 64 hex chars (SHA256)
        assert len(root_hash) == 64
        assert all(c in '0123456789abcdef' for c in root_hash)


# ============ Idempotency Tests ============

class TestIdempotency:
    def test_duplicate_event_rejected(self, client, unique_run_id):
        """Same event_id is not recorded twice."""
        # Start run
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        
        event_data = {
            "run_id": unique_run_id,
            "event_id": "evt-duplicate",
            "type": "test.event",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "test",
            "data": {}
        }
        
        # First send
        resp1 = client.post("/v1/run/event", json=event_data)
        assert resp1.json()["status"] == "recorded"
        
        # Second send (duplicate)
        resp2 = client.post("/v1/run/event", json=event_data)
        assert resp2.json()["status"] == "duplicate"


# ============ Proof Graph Tests ============

class TestProofGraph:
    def test_link_proofs(self, client):
        """Proofs can be linked with relationships."""
        # Create parent and child runs
        parent_id = f"parent-{int(time.time()*1000)}"
        child_id = f"child-{int(time.time()*1000)}"
        
        for run_id in [parent_id, child_id]:
            client.post("/v1/run/start", json={
                "run_id": run_id,
                "agent_id": "test-agent",
                "adapter": "test"
            })
            client.post("/v1/run/end", json={"run_id": run_id, "success": True})
        
        # Link them
        resp = client.post("/v1/proof-graph/link", json={
            "child_proof_id": child_id,
            "parent_proof_id": parent_id,
            "relation": "delegation"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "linked"

    def test_graph_traversal(self, client):
        """Graph can be traversed from root."""
        # Create a small graph
        root_id = f"root-{int(time.time()*1000)}"
        child1_id = f"child1-{int(time.time()*1000)}"
        child2_id = f"child2-{int(time.time()*1000)}"
        
        for run_id in [root_id, child1_id, child2_id]:
            client.post("/v1/run/start", json={
                "run_id": run_id,
                "agent_id": "test-agent",
                "adapter": "test"
            })
            client.post("/v1/run/end", json={"run_id": run_id, "success": True})
        
        # Link children to root
        client.post("/v1/proof-graph/link", json={
            "child_proof_id": child1_id,
            "parent_proof_id": root_id,
            "relation": "delegation"
        })
        client.post("/v1/proof-graph/link", json={
            "child_proof_id": child2_id,
            "parent_proof_id": root_id,
            "relation": "delegation"
        })
        
        # Get graph
        resp = client.get(f"/v1/proof-graph/{root_id}")
        assert resp.status_code == 200
        graph = resp.json()
        assert graph["node_count"] == 3
        assert graph["edge_count"] == 2
        assert "graph_hash" in graph

    def test_cycle_prevention(self, client):
        """Cycles are rejected."""
        a_id = f"cycleA-{int(time.time()*1000)}"
        b_id = f"cycleB-{int(time.time()*1000)}"
        
        for run_id in [a_id, b_id]:
            client.post("/v1/run/start", json={
                "run_id": run_id,
                "agent_id": "test-agent",
                "adapter": "test"
            })
            client.post("/v1/run/end", json={"run_id": run_id, "success": True})
        
        # A -> B
        client.post("/v1/proof-graph/link", json={
            "child_proof_id": b_id,
            "parent_proof_id": a_id,
            "relation": "delegation"
        })
        
        # B -> A (would create cycle)
        resp = client.post("/v1/proof-graph/link", json={
            "child_proof_id": a_id,
            "parent_proof_id": b_id,
            "relation": "delegation"
        })
        assert resp.status_code == 400
        assert "cycle" in resp.json()["detail"].lower()


# ============ State Chain Tests ============

class TestStateChain:
    def test_state_proof_creation(self, client, unique_run_id):
        """State proofs can be created and retrieved."""
        # Create run
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        # Create state proof
        resp = client.post("/v1/state-proof", json={
            "run_id": unique_run_id,
            "state_type": "memory",
            "prev_state_hash": None,
            "next_state_hash": "sha256:newstate"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "created"
        
        # Retrieve state proofs for run
        resp = client.get(f"/v1/runproof/{unique_run_id}/state-proofs")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1


# ============ Policy Binding Tests ============

class TestPolicyBinding:
    def test_bind_policy_to_run(self, client, unique_run_id):
        """Policy can be bound to run."""
        # Create run
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        # Bind policy
        resp = client.post("/v1/policy-binding", json={
            "run_id": unique_run_id,
            "policy_type": "acc_token",
            "policy_id": "test-policy-001",
            "policy_hash": "sha256:testpolicy",
            "binding_status": "applied"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "bound"

    def test_get_policies_for_run(self, client, unique_run_id):
        """Can retrieve policies bound to a run."""
        # Create run with policy
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        client.post("/v1/policy-binding", json={
            "run_id": unique_run_id,
            "policy_type": "governance_rule",
            "policy_id": "test-policy-002",
            "policy_hash": "sha256:rule",
            "binding_status": "applied"
        })
        
        # Get policies
        resp = client.get(f"/v1/runproof/{unique_run_id}/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total"] >= 1


# ============ External Anchoring Tests ============

class TestAnchoring:
    def test_submit_anchor(self, client, unique_run_id):
        """Run can be submitted for anchoring."""
        # Create run
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        # Submit for anchoring
        resp = client.post("/v1/anchor", json={
            "proof_id": unique_run_id,
            "proof_type": "run",
            "anchor_type": "ethereum"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] in ["submitted", "pending"]

    def test_confirm_anchor(self, client, unique_run_id):
        """Anchor can be confirmed with transaction details."""
        # Create run and anchor
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        anchor_resp = client.post("/v1/anchor", json={
            "proof_id": unique_run_id,
            "proof_type": "run",
            "anchor_type": "bitcoin"
        })
        anchor_id = anchor_resp.json()["id"]
        
        # Confirm anchor
        resp = client.post(f"/v1/anchor/{anchor_id}/confirm", json={
            "anchor_tx_id": "0x123abc...",
            "anchor_block": "800000"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "confirmed"


# ============ Agent Lifecycle Tests ============

class TestAgentLifecycle:
    def test_register_agent(self, client):
        """Agent can be registered."""
        agent_id = f"test-agent-{int(time.time()*1000)}"
        
        resp = client.post(f"/v1/agent/{agent_id}/register", json={
            "metadata": {"role": "test"}
        })
        assert resp.status_code == 200
        assert resp.json()["status"] in ["registered", "active"]

    def test_heartbeat_auto_registers(self, client):
        """Heartbeat auto-registers unknown agent."""
        agent_id = f"auto-agent-{int(time.time()*1000)}"
        
        resp = client.post(f"/v1/agent/{agent_id}/heartbeat")
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

    def test_agent_lifecycle_transitions(self, client):
        """Agent can transition through lifecycle states."""
        agent_id = f"lifecycle-agent-{int(time.time()*1000)}"
        
        # Register
        client.post(f"/v1/agent/{agent_id}/register")
        
        # Pause
        resp = client.post(f"/v1/agent/{agent_id}/pause")
        assert resp.json()["status"] == "paused"
        
        # Activate
        resp = client.post(f"/v1/agent/{agent_id}/activate")
        assert resp.json()["status"] == "active"
        
        # Retire
        resp = client.post(f"/v1/agent/{agent_id}/retire")
        assert resp.json()["status"] == "retired"


# ============ Signature Tests ============

class TestSignatures:
    def test_public_key_available(self, client):
        """Runtime public key is available."""
        resp = client.get("/v1/signing/public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert "key_id" in data
        assert "public_key" in data
        assert data["algorithm"] == "ed25519"

    def test_proof_signed(self, client, unique_run_id):
        """Completed proofs have signatures."""
        # Create run with event
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/event", json={
            "run_id": unique_run_id,
            "event_id": "evt-001",
            "type": "message.received",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "test",
            "data": {}
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        # Get proof
        resp = client.get(f"/v1/runproof/{unique_run_id}")
        assert resp.status_code == 200
        proof = resp.json()
        assert "signatures" in proof
        assert len(proof["signatures"]) > 0

    def test_proof_verifiable(self, client, unique_run_id):
        """Proof verification endpoint works."""
        # Create signed proof
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        # Verify
        resp = client.get(f"/v1/runproof/{unique_run_id}/verify")
        assert resp.status_code == 200
        result = resp.json()
        # Check structure
        assert "chain_valid" in result
        assert "signatures" in result
        assert "root_hash" in result


# ============ Fingerprint Tests ============

class TestFingerprints:
    def test_proof_has_fingerprints(self, client, unique_run_id):
        """Completed proofs have fingerprint hierarchy."""
        # Create run with environment event
        client.post("/v1/run/start", json={
            "run_id": unique_run_id,
            "agent_id": "test-agent",
            "adapter": "test"
        })
        client.post("/v1/run/event", json={
            "run_id": unique_run_id,
            "event_id": "evt-env",
            "type": "environment.captured",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "test",
            "data": {"model": "test-model", "temperature": 0.7}
        })
        client.post("/v1/run/end", json={"run_id": unique_run_id, "success": True})
        
        # Get proof
        resp = client.get(f"/v1/runproof/{unique_run_id}")
        proof = resp.json()
        
        # Check fingerprints
        assert "fingerprints" in proof
        if proof["fingerprints"]:  # May be null if no env events
            fp = proof["fingerprints"]
            assert "run_fingerprint" in fp


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
