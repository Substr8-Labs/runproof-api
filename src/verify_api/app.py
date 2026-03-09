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
# In-memory proof store (replace with DB in production)
# ═══════════════════════════════════════════════════════════════════════════════


_proof_store: dict[str, dict] = {}


def get_proof(proof_id: str) -> dict:
    """Get proof from store."""
    if proof_id not in _proof_store:
        raise HTTPException(status_code=404, detail=f"Proof not found: {proof_id}")
    return _proof_store[proof_id]


def store_proof(proof: dict) -> str:
    """Store proof and return ID."""
    proof_id = proof.get("header", {}).get("proof_id")
    if not proof_id:
        raise HTTPException(status_code=400, detail="Proof missing proof_id")
    _proof_store[proof_id] = proof
    return proof_id


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
        "stored_proofs": len(_proof_store),
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
    """
    proof = request.proof
    
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


@app.get("/proof/{proof_id}", response_model=FullVerificationResponse)
def get_full_proof(proof_id: str):
    """
    Get all 4 views for a proof.
    
    Returns: summary, timeline, lineage, and report views.
    """
    proof = get_proof(proof_id)
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
