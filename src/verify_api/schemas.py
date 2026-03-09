"""
API schemas for the 4 verification views.

View 1: Summary - The "green tick" page
View 2: Timeline - Chronological events
View 3: Lineage - Parent/child tree
View 4: Report - Audit checks
"""

from datetime import datetime
from typing import Any, Literal
from enum import Enum
from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════════════════════
# View 1: Verification Summary
# ═══════════════════════════════════════════════════════════════════════════════


class VerificationStatus(str, Enum):
    """Overall verification status."""
    VERIFIED = "verified"
    INVALID = "invalid"
    PARTIAL = "partial"
    PENDING = "pending"


class AnchorStatus(str, Enum):
    """Anchor/registry status."""
    NOT_ANCHORED = "not_anchored"
    ANCHORED = "anchored"
    PENDING = "pending"
    FAILED = "failed"


class PaymentStatus(str, Enum):
    """Settlement/payment status."""
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"
    SETTLED = "settled"
    FAILED = "failed"
    DISPUTED = "disputed"


class SummaryView(BaseModel):
    """View 1: Verification Summary.
    
    The first thing a user sees - the "green tick" page.
    """
    
    # Core status
    status: VerificationStatus = Field(..., description="Overall verification status")
    status_message: str = Field(..., description="Human-readable status message")
    
    # Identifiers
    proof_id: str = Field(..., description="Unique proof identifier")
    run_id: str = Field(..., description="Run identifier")
    agent_id: str = Field(..., description="Agent identifier")
    runtime: str = Field(..., description="Runtime (langgraph, openclaw, etc.)")
    
    # Timing
    started_at: datetime = Field(..., description="Run start time")
    ended_at: datetime | None = Field(None, description="Run end time")
    duration_ms: int | None = Field(None, description="Duration in milliseconds")
    
    # Status details
    run_status: str = Field(..., description="Run completion status")
    
    # Signer info
    signer_key_id: str | None = Field(None, description="Signing key ID")
    signer_issuer: str | None = Field(None, description="Key issuer")
    
    # Policy
    policy_id: str | None = Field(None, description="Policy profile ID")
    policy_hash: str | None = Field(None, description="Policy hash")
    
    # Anchoring
    anchor_status: AnchorStatus = Field(AnchorStatus.NOT_ANCHORED)
    anchor_reference: str | None = Field(None, description="Registry/ledger reference")
    
    # Payment (if applicable)
    payment_status: PaymentStatus = Field(PaymentStatus.NOT_APPLICABLE)
    settlement_reference: str | None = Field(None)
    
    # Quick stats
    event_count: int = Field(0, description="Number of trace events")
    child_count: int = Field(0, description="Number of child runs")


# ═══════════════════════════════════════════════════════════════════════════════
# View 2: Execution Timeline
# ═══════════════════════════════════════════════════════════════════════════════


class TimelineEvent(BaseModel):
    """Single event in the timeline."""
    
    seq: int = Field(..., description="Sequence number")
    event_id: str = Field(..., description="Event identifier")
    event_type: str = Field(..., description="Event type")
    timestamp: datetime = Field(..., description="Event timestamp")
    
    # Context
    agent_id: str | None = Field(None)
    node_name: str | None = Field(None)
    tool_name: str | None = Field(None)
    
    # Payload
    payload_summary: str | None = Field(None, description="Human-readable summary")
    payload_hash: str | None = Field(None)
    
    # Hash chain
    entry_hash: str = Field(..., description="This entry's hash")
    prev_hash: str | None = Field(None, description="Previous entry's hash")
    
    # Status
    is_error: bool = Field(False)
    is_delegation: bool = Field(False)
    
    # Linked references
    child_run_id: str | None = Field(None)
    linked_proof_id: str | None = Field(None)


class TimelineView(BaseModel):
    """View 2: Execution Timeline.
    
    Chronological ordered list of events - the developer view.
    """
    
    run_id: str
    total_events: int
    events: list[TimelineEvent]
    
    # Timeline stats
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    
    # Error summary
    error_count: int = 0
    delegation_count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# View 3: Lineage / Tree View
# ═══════════════════════════════════════════════════════════════════════════════


class LineageNode(BaseModel):
    """Node in the lineage tree."""
    
    run_id: str
    agent_id: str
    runtime: str
    status: str
    
    # Timing
    started_at: datetime | None = None
    ended_at: datetime | None = None
    
    # Proof info
    proof_id: str | None = None
    proof_verified: bool | None = None
    
    # Settlement
    settlement_point: bool = Field(False, description="Is this a settlement boundary?")
    
    # Tree structure
    parent_run_id: str | None = None
    children: list["LineageNode"] = Field(default_factory=list)
    depth: int = Field(0, description="Depth in tree (0 = root)")


class LineageView(BaseModel):
    """View 3: Lineage / Tree View.
    
    Shows parent/child relationships, delegations, and settlement points.
    """
    
    root: LineageNode
    
    # Stats
    total_runs: int = 1
    max_depth: int = 0
    total_delegations: int = 0
    verified_proofs: int = 0
    pending_proofs: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# View 4: Verification Report
# ═══════════════════════════════════════════════════════════════════════════════


class CheckStatus(str, Enum):
    """Individual check status."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    PENDING = "pending"


class VerificationCheck(BaseModel):
    """Single verification check result."""
    
    name: str = Field(..., description="Check name")
    status: CheckStatus = Field(..., description="Check status")
    message: str = Field(..., description="Human-readable result")
    
    # Details
    expected: str | None = Field(None)
    actual: str | None = Field(None)
    details: dict[str, Any] = Field(default_factory=dict)
    
    # For technical mode
    technical_details: str | None = Field(None)


class ReportView(BaseModel):
    """View 4: Verification Report.
    
    The audit panel - all verification checks with pass/fail status.
    """
    
    proof_id: str
    overall_status: VerificationStatus
    verified_at: datetime
    
    # Checks
    checks: list[VerificationCheck]
    
    # Summary
    passed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    
    # Human mode summary
    human_summary: str = Field(..., description="Plain language summary")
    
    # Technical details (for technical mode)
    proof_hash: str | None = None
    event_root: str | None = None
    signature_algorithm: str | None = None


# ═══════════════════════════════════════════════════════════════════════════════
# Combined Response
# ═══════════════════════════════════════════════════════════════════════════════


class FullVerificationResponse(BaseModel):
    """Complete verification response with all views."""
    
    summary: SummaryView
    timeline: TimelineView
    lineage: LineageView
    report: ReportView
