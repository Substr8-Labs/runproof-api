"""
Comprehensive test suite for verify-api.

Tests all endpoints and ensures:
- Correct data returned for UI
- Merkle tree verification works
- Hash computations are correct
- Event flow matches spec
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from runproof_api import app
from runproof_api.schemas import VerificationStatus


client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures - Create valid RunProof
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def valid_proof():
    """Create a valid RunProof using substr8-core."""
    from substr8_core import (
        RunProof, RunProofHeader, TraceEntry, EventType, RunStatus,
        TriggerType, RedactionMode, SignatureAlgorithm,
        Identity, Signer, Context, Outputs, Commitments, Signature, Metadata,
        sha256_json, compute_merkle_root, KeyPair,
    )
    from substr8_core.crypto.hashing import compute_entry_hash
    
    proof_id = "proof_test_123456"
    run_id = "run_test_abcdef"
    
    # Build trace entries with proper hash chain
    entries = []
    prev_hash = None
    events = [
        (EventType.RUN_STARTED, {"agent_id": "test-agent"}),
        (EventType.NODE_STARTED, {"node": "process"}),
        (EventType.TOOL_CALL_STARTED, {"tool": "search"}),
        (EventType.TOOL_CALL_COMPLETED, {"tool": "search", "result_hash": "abc123"}),
        (EventType.NODE_COMPLETED, {"node": "process"}),
        (EventType.RUN_COMPLETED, {"status": "completed"}),
    ]
    
    for i, (event_type, payload) in enumerate(events):
        timestamp = datetime.now(timezone.utc)
        timestamp_str = timestamp.isoformat().replace("+00:00", "Z")
        payload_hash = sha256_json(payload)
        
        entry_hash = compute_entry_hash(
            seq=i + 1,
            event_type=event_type.value,
            timestamp=timestamp_str,
            prev_hash=prev_hash,
            payload_hash=payload_hash,
        )
        
        entry = TraceEntry(
            seq=i + 1,
            event_id=f"evt_{i:012d}",
            type=event_type,
            timestamp=timestamp,
            prev_hash=prev_hash,
            payload_hash=payload_hash,
            payload=payload,
            entry_hash=entry_hash,
        )
        entries.append(entry)
        prev_hash = entry_hash
    
    # Compute merkle root
    entry_hashes = [e.entry_hash for e in entries]
    event_root = compute_merkle_root(entry_hashes)
    
    # Generate key and sign
    key_pair = KeyPair.generate(f"test_key_{proof_id}")
    
    started_at = datetime.now(timezone.utc)
    
    header = RunProofHeader(
        proof_id=proof_id,
        run_id=run_id,
        agent_id="test-agent",
        runtime="langgraph",
        runtime_version="0.1.0",
        started_at=started_at,
        ended_at=datetime.now(timezone.utc),
        status=RunStatus.COMPLETED,
    )
    
    signer = Signer(
        key_id=key_pair.key_id,
        public_key=key_pair.public_key_hex,
        issuer="test-suite",
    )
    
    context = Context(
        trigger_type=TriggerType.API,
        input_hash=sha256_json({"test": "input"}),
        input_redaction_mode=RedactionMode.HASHED,
    )
    
    outputs = Outputs(
        result_hash=sha256_json({"test": "output"}),
        result_redaction_mode=RedactionMode.HASHED,
    )
    
    # Build proof hash and sign
    proof_envelope = {
        "schema_version": "runproof/v2",
        "header": header.model_dump(mode="json"),
        "identity": {"signer": signer.model_dump(mode="json")},
        "context": context.model_dump(mode="json"),
        "trace_root": event_root,
        "outputs": outputs.model_dump(mode="json"),
    }
    proof_hash = sha256_json(proof_envelope)
    signature_value = key_pair.sign(proof_hash.encode())
    
    commitments = Commitments(
        event_root=event_root,
        proof_hash=proof_hash,
        signature=Signature(
            algorithm=SignatureAlgorithm.ED25519,
            value=signature_value,
        ),
    )
    
    proof = RunProof(
        schema_version="runproof/v2",
        header=header,
        identity=Identity(signer=signer),
        context=context,
        trace=entries,
        outputs=outputs,
        commitments=commitments,
        metadata=Metadata(tags=["test"]),
    )
    
    return proof.model_dump(mode="json")


@pytest.fixture
def invalid_proof():
    """Create a proof with broken hash chain."""
    valid = {
        "schema_version": "runproof/v2",
        "header": {
            "proof_id": "proof_invalid",
            "run_id": "run_invalid",
            "agent_id": "test",
            "runtime": "test",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
        },
        "identity": {"signer": {"key_id": "test", "public_key": "ed25519:abc", "issuer": "test"}},
        "context": {"trigger_type": "api", "input_hash": "sha256:abc", "input_redaction_mode": "hashed"},
        "trace": [
            {
                "seq": 1,
                "event_id": "evt_1",
                "type": "run_started",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "entry_hash": "sha256:wrong_hash",  # Incorrect hash
            }
        ],
        "outputs": {"result_hash": "sha256:abc", "result_redaction_mode": "hashed"},
        "commitments": {
            "event_root": "sha256:wrong",
            "proof_hash": "sha256:wrong",
            "signature": {"algorithm": "ed25519", "value": "invalid"},
        },
    }
    return valid


# ═══════════════════════════════════════════════════════════════════════════════
# Health & Stats Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestHealthEndpoints:
    """Test health and status endpoints."""
    
    def test_health_returns_healthy(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
    
    def test_stats_returns_count(self):
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json()
        assert "stored_proofs" in data
        assert isinstance(data["stored_proofs"], int)


# ═══════════════════════════════════════════════════════════════════════════════
# Verification Endpoint Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifyEndpoint:
    """Test proof verification."""
    
    def test_verify_valid_proof(self, valid_proof):
        """Valid proof should return verified status."""
        response = client.post("/verify", json={"proof": valid_proof})
        assert response.status_code == 200
        data = response.json()
        
        assert data["valid"] is True
        assert data["status"] == "verified"
        assert data["proof_id"] == valid_proof["header"]["proof_id"]
        assert "message" in data
    
    def test_verify_empty_proof_fails(self):
        """Empty proof should fail."""
        response = client.post("/verify", json={"proof": {}})
        assert response.status_code == 400
    
    def test_verify_stores_proof(self, valid_proof):
        """Verified proof should be stored for retrieval."""
        # Verify
        response = client.post("/verify", json={"proof": valid_proof})
        assert response.status_code == 200
        proof_id = response.json()["proof_id"]
        
        # Should be retrievable
        response = client.get(f"/proof/{proof_id}")
        assert response.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# View 1: Summary Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSummaryView:
    """Test View 1: Verification Summary."""
    
    def test_summary_returns_all_fields(self, valid_proof):
        # Store proof first
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/summary")
        assert response.status_code == 200
        data = response.json()
        
        # Required fields
        assert "status" in data
        assert "status_message" in data
        assert "proof_id" in data
        assert "run_id" in data
        assert "agent_id" in data
        assert "runtime" in data
        assert "started_at" in data
        assert "run_status" in data
        assert "event_count" in data
    
    def test_summary_verified_status(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/summary")
        data = response.json()
        
        assert data["status"] == "verified"
        assert "verified" in data["status_message"].lower() or "authentic" in data["status_message"].lower()
    
    def test_summary_event_count_matches(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/summary")
        data = response.json()
        
        expected_count = len(valid_proof["trace"])
        assert data["event_count"] == expected_count


# ═══════════════════════════════════════════════════════════════════════════════
# View 2: Timeline Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTimelineView:
    """Test View 2: Execution Timeline."""
    
    def test_timeline_returns_events(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/timeline")
        assert response.status_code == 200
        data = response.json()
        
        assert "events" in data
        assert "total_events" in data
        assert len(data["events"]) == data["total_events"]
    
    def test_timeline_events_have_required_fields(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/timeline")
        events = response.json()["events"]
        
        for event in events:
            assert "seq" in event
            assert "event_id" in event
            assert "event_type" in event
            assert "timestamp" in event
            assert "entry_hash" in event
    
    def test_timeline_preserves_order(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/timeline")
        events = response.json()["events"]
        
        # Events should be in sequence order
        for i, event in enumerate(events):
            assert event["seq"] == i + 1
    
    def test_timeline_hash_chain_linked(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/timeline")
        events = response.json()["events"]
        
        # First event has no prev_hash
        assert events[0]["prev_hash"] is None
        
        # Subsequent events link to previous
        for i in range(1, len(events)):
            assert events[i]["prev_hash"] == events[i-1]["entry_hash"]
    
    def test_timeline_pagination(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        # Get with limit
        response = client.get(f"/proof/{proof_id}/timeline?limit=2&offset=0")
        data = response.json()
        assert len(data["events"]) <= 2
        
        # Get with offset
        response = client.get(f"/proof/{proof_id}/timeline?limit=2&offset=2")
        data2 = response.json()
        
        # Should be different events (if enough exist)
        if data["total_events"] > 2:
            assert data["events"][0]["seq"] != data2["events"][0]["seq"]


# ═══════════════════════════════════════════════════════════════════════════════
# View 3: Lineage Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLineageView:
    """Test View 3: Lineage / Tree View."""
    
    def test_lineage_returns_root(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/lineage")
        assert response.status_code == 200
        data = response.json()
        
        assert "root" in data
        assert "total_runs" in data
    
    def test_lineage_root_has_required_fields(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/lineage")
        root = response.json()["root"]
        
        assert "run_id" in root
        assert "agent_id" in root
        assert "runtime" in root
        assert "status" in root
        assert "proof_verified" in root
    
    def test_lineage_verification_status(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/lineage")
        data = response.json()
        
        assert data["root"]["proof_verified"] is True
        assert data["verified_proofs"] >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# View 4: Report Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestReportView:
    """Test View 4: Verification Report."""
    
    def test_report_returns_checks(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/report")
        assert response.status_code == 200
        data = response.json()
        
        assert "checks" in data
        assert "overall_status" in data
        assert "human_summary" in data
    
    def test_report_checks_have_status(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/report")
        checks = response.json()["checks"]
        
        for check in checks:
            assert "name" in check
            assert "status" in check
            assert "message" in check
            assert check["status"] in ["passed", "failed", "skipped", "pending"]
    
    def test_report_valid_proof_passes_checks(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/report")
        data = response.json()
        
        assert data["overall_status"] == "verified"
        assert data["passed_count"] > 0
    
    def test_report_has_human_summary(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/report")
        data = response.json()
        
        assert len(data["human_summary"]) > 0
        # Should contain human-readable content
        assert any(word in data["human_summary"].lower() for word in ["valid", "verified", "proof", "execution"])
    
    def test_report_has_technical_details(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}/report?mode=technical")
        data = response.json()
        
        # Should have technical fields
        assert "proof_hash" in data
        assert "event_root" in data


# ═══════════════════════════════════════════════════════════════════════════════
# Full Response Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFullResponse:
    """Test combined endpoint returning all views."""
    
    def test_full_response_has_all_views(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}")
        assert response.status_code == 200
        data = response.json()
        
        assert "summary" in data
        assert "timeline" in data
        assert "lineage" in data
        assert "report" in data
    
    def test_views_are_consistent(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/proof/{proof_id}")
        data = response.json()
        
        # All views should reference same proof
        assert data["summary"]["proof_id"] == proof_id
        assert data["timeline"]["run_id"] == data["summary"]["run_id"]
        assert data["lineage"]["root"]["run_id"] == data["summary"]["run_id"]
        assert data["report"]["proof_id"] == proof_id


# ═══════════════════════════════════════════════════════════════════════════════
# Badge Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestBadge:
    """Test badge generation."""
    
    def test_badge_verified(self, valid_proof):
        client.post("/verify", json={"proof": valid_proof})
        proof_id = valid_proof["header"]["proof_id"]
        
        response = client.get(f"/badge/{proof_id}")
        assert response.status_code == 200
        data = response.json()
        
        assert data["label"] == "Substr8"
        assert data["message"] == "verified"
        assert data["color"] == "brightgreen"
    
    def test_badge_not_found(self):
        response = client.get("/badge/nonexistent")
        assert response.status_code == 200
        data = response.json()
        
        assert data["message"] == "not found"
        assert data["color"] == "lightgrey"


# ═══════════════════════════════════════════════════════════════════════════════
# Error Handling Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Test error cases."""
    
    def test_proof_not_found(self):
        response = client.get("/proof/nonexistent")
        assert response.status_code == 404
    
    def test_invalid_json(self):
        response = client.post("/verify", content="not json", headers={"Content-Type": "application/json"})
        assert response.status_code == 422
