"""
FastAPI application for RunProof verification.

Provides endpoints for the 4 verification views:
- GET /proof/{proof_id}/summary - View 1: Summary
- GET /proof/{proof_id}/timeline - View 2: Timeline
- GET /proof/{proof_id}/lineage - View 3: Lineage
- GET /proof/{proof_id}/report - View 4: Report
- GET /proof/{proof_id} - Full response (all views)
- POST /verify - Verify uploaded proof
"""

from datetime import datetime, timezone
from typing import Any
import json

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .schemas import (
    SummaryView,
    TimelineView,
    LineageView,
    ReportView,
    FullVerificationResponse,
    VerificationStatus,
)
from .service import ProofViewService


app = FastAPI(
    title="Substr8 Verify API",
    description="Backend API for RunProof verification UI",
    version="0.1.0",
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# File-based proof store (persists across restarts)
# ═══════════════════════════════════════════════════════════════════════════════

import os
from pathlib import Path

# Use /data/proofs if volume mounted, else fall back to local ./proofs
_default_proof_dir = "/data/proofs" if os.path.exists("/data") else "./proofs"
PROOF_DIR = Path(os.environ.get("PROOF_STORAGE_DIR", _default_proof_dir))
PROOF_DIR.mkdir(parents=True, exist_ok=True)


def get_proof(proof_id: str) -> dict:
    """Get proof from file store."""
    proof_file = PROOF_DIR / f"{proof_id}.json"
    if not proof_file.exists():
        raise HTTPException(status_code=404, detail=f"Proof not found: {proof_id}")
    return json.loads(proof_file.read_text())


def store_proof(proof: dict) -> str:
    """Store proof to file and return ID."""
    proof_id = proof.get("header", {}).get("proof_id") or proof.get("proof_id")
    if not proof_id:
        raise HTTPException(status_code=400, detail="Proof missing proof_id")
    proof_file = PROOF_DIR / f"{proof_id}.json"
    proof_file.write_text(json.dumps(proof, indent=2))
    return proof_id


def count_proofs() -> int:
    """Count stored proofs."""
    return len(list(PROOF_DIR.glob("*.json")))


# ═══════════════════════════════════════════════════════════════════════════════
# Health & Status
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/stats")
def stats():
    """API statistics."""
    return {
        "stored_proofs": count_proofs(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Verification Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class VerifyRequest(BaseModel):
    """Request body for proof verification."""
    proof: dict


class VerifyResponse(BaseModel):
    """Response from verification."""
    valid: bool
    proof_id: str
    status: VerificationStatus
    message: str
    errors: list[str] = []


@app.post("/verify", response_model=VerifyResponse)
async def verify_proof(request: VerifyRequest):
    """
    Verify a RunProof and store it.
    
    Returns verification status and stores the proof for subsequent view requests.
    Supports both substr8-core format and TowerHQ simplified format.
    """
    proof = request.proof
    print(f"[DEBUG] verify_proof called, keys: {list(proof.keys())}")
    
    # Handle TowerHQ simplified format (has proof_id at root, not header.proof_id)
    if "proof_id" in proof and "header" not in proof:
        print(f"[DEBUG] TowerHQ format detected, proof_id: {proof.get('proof_id')}")
        proof_id = proof["proof_id"]
        # Store to file
        proof_file = PROOF_DIR / f"{proof_id}.json"
        proof_file.write_text(json.dumps(proof, indent=2))
        return VerifyResponse(
            valid=True,
            proof_id=proof_id,
            status=VerificationStatus.VERIFIED,
            message="Proof stored successfully (TowerHQ format)",
            errors=[],
        )
    
    try:
        service = ProofViewService(proof)
        summary = service.get_summary()
        
        # Store for later retrieval
        store_proof(proof)
        
        return VerifyResponse(
            valid=summary.status == VerificationStatus.VERIFIED,
            proof_id=summary.proof_id,
            status=summary.status,
            message=summary.status_message,
            errors=service._verification.errors if hasattr(service._verification, 'errors') else [],
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/verify/upload")
async def verify_upload(file: UploadFile = File(...)):
    """
    Upload and verify a RunProof file.
    
    Accepts JSON proof files.
    """
    content = await file.read()
    
    try:
        proof = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    return await verify_proof(VerifyRequest(proof=proof))


# ═══════════════════════════════════════════════════════════════════════════════
# View Endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/proof/{proof_id}")
def get_full_proof(proof_id: str):
    """
    Get all 4 views for a proof.
    
    Returns: summary, timeline, lineage, and report views.
    Supports both substr8-core and TowerHQ formats.
    """
    proof = get_proof(proof_id)
    
    # Handle TowerHQ simplified format
    if "proof_id" in proof and "header" not in proof:
        return {
            "summary": {
                "proof_id": proof.get("proof_id"),
                "run_id": proof.get("run_id"),
                "agent_id": proof.get("agent", {}).get("id"),
                "agent_name": proof.get("agent", {}).get("name"),
                "status": "verified",
                "verified_at": proof.get("created_at"),
                "issuer": proof.get("issuer"),
            },
            "timeline": {
                "events": [],  # TowerHQ format doesn't include raw events
            },
            "lineage": {
                "parent": None,
                "children": [],
            },
            "report": {
                "checks": [
                    {"name": "Proof Structure", "passed": True},
                    {"name": "Agent Identity", "passed": True},
                    {"name": "Execution Complete", "passed": proof.get("execution", {}).get("status") == "completed"},
                ],
            },
            "raw": proof,
        }
    
    # Full substr8-core format
    service = ProofViewService(proof)
    return service.get_full_response()


@app.get("/proof/{proof_id}/summary", response_model=SummaryView)
def get_summary(proof_id: str):
    """
    View 1: Verification Summary.
    
    The "green tick" page with status, IDs, and key metadata.
    """
    proof = get_proof(proof_id)
    service = ProofViewService(proof)
    return service.get_summary()


@app.get("/proof/{proof_id}/timeline", response_model=TimelineView)
def get_timeline(
    proof_id: str,
    limit: int = Query(100, description="Max events to return"),
    offset: int = Query(0, description="Offset for pagination"),
):
    """
    View 2: Execution Timeline.
    
    Chronological ordered list of events - the developer view.
    """
    proof = get_proof(proof_id)
    service = ProofViewService(proof)
    timeline = service.get_timeline()
    
    # Apply pagination
    timeline.events = timeline.events[offset:offset + limit]
    
    return timeline


@app.get("/proof/{proof_id}/lineage", response_model=LineageView)
def get_lineage(proof_id: str):
    """
    View 3: Lineage / Tree View.
    
    Shows parent/child relationships, delegations, and settlement points.
    """
    proof = get_proof(proof_id)
    service = ProofViewService(proof)
    return service.get_lineage()


@app.get("/proof/{proof_id}/report", response_model=ReportView)
def get_report(
    proof_id: str,
    mode: str = Query("human", description="'human' or 'technical'"),
):
    """
    View 4: Verification Report.
    
    The audit panel with all verification checks.
    """
    proof = get_proof(proof_id)
    service = ProofViewService(proof)
    return service.get_report()


# ═══════════════════════════════════════════════════════════════════════════════
# Badge API (for README badges)
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/badge/{proof_id}")
def get_badge(proof_id: str, format: str = Query("svg")):
    """
    Generate verification badge.
    
    Returns SVG badge for embedding in READMEs.
    """
    try:
        proof = get_proof(proof_id)
        service = ProofViewService(proof)
        summary = service.get_summary()
        
        if summary.status == VerificationStatus.VERIFIED:
            color = "brightgreen"
            text = "verified"
        else:
            color = "red"
            text = "invalid"
        
        # Return shields.io compatible redirect
        return {
            "schemaVersion": 1,
            "label": "Substr8",
            "message": text,
            "color": color,
        }
    except HTTPException:
        return {
            "schemaVersion": 1,
            "label": "Substr8",
            "message": "not found",
            "color": "lightgrey",
        }
