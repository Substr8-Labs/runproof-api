"""
Service layer for transforming RunProof into UI views.
"""

from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass

# Type alias - we work with dicts, not Pydantic models
RunProof = dict

@dataclass
class VerificationResult:
    """Mock verification result."""
    valid: bool = True
    errors: list = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

def verify_runproof(proof: dict) -> VerificationResult:
    """Simple verification - checks structure exists."""
    errors = []
    if "header" not in proof and "proof_id" not in proof:
        errors.append("Missing header or proof_id")
    return VerificationResult(valid=len(errors) == 0, errors=errors)

from .schemas import (
    SummaryView,
    TimelineView,
    TimelineEvent,
    LineageView,
    LineageNode,
    ReportView,
    VerificationCheck,
    FullVerificationResponse,
    VerificationStatus,
    CheckStatus,
    AnchorStatus,
    PaymentStatus,
)


class ProofViewService:
    """Transforms RunProof into UI views."""
    
    def __init__(self, proof: RunProof | dict):
        """Initialize with a RunProof (Pydantic model or dict)."""
        if isinstance(proof, dict):
            self.proof_dict = proof
            self.proof = RunProof(**proof)
        else:
            self.proof = proof
            self.proof_dict = proof.model_dump(mode="json")
        
        # Run verification
        self._verification = verify_runproof(self.proof_dict)
    
    def get_summary(self) -> SummaryView:
        """Generate View 1: Verification Summary."""
        header = self.proof.header
        identity = self.proof.identity
        
        # Calculate duration
        duration_ms = None
        if header.started_at and header.ended_at:
            delta = header.ended_at - header.started_at
            duration_ms = int(delta.total_seconds() * 1000)
        
        # Determine status
        status = VerificationStatus.VERIFIED if self._verification.valid else VerificationStatus.INVALID
        status_message = self._generate_status_message()
        
        return SummaryView(
            status=status,
            status_message=status_message,
            proof_id=header.proof_id,
            run_id=header.run_id,
            agent_id=header.agent_id,
            runtime=header.runtime,
            started_at=header.started_at,
            ended_at=header.ended_at,
            duration_ms=duration_ms,
            run_status=header.status.value if hasattr(header.status, 'value') else str(header.status),
            signer_key_id=identity.signer.key_id if identity.signer else None,
            signer_issuer=identity.signer.issuer if identity.signer else None,
            policy_id=identity.policy.policy_id if identity.policy else None,
            policy_hash=identity.policy.policy_hash if identity.policy else None,
            anchor_status=AnchorStatus.NOT_ANCHORED,  # TODO: Check anchors
            event_count=len(self.proof.trace),
            child_count=0,  # TODO: Count from lineage
        )
    
    def get_timeline(self) -> TimelineView:
        """Generate View 2: Execution Timeline."""
        events = []
        error_count = 0
        delegation_count = 0
        
        for entry in self.proof.trace:
            event_type = entry.type.value if hasattr(entry.type, 'value') else str(entry.type)
            
            # Determine if error or delegation
            is_error = "failed" in event_type or "error" in event_type
            is_delegation = "delegation" in event_type or "child" in event_type or "spawn" in event_type
            
            if is_error:
                error_count += 1
            if is_delegation:
                delegation_count += 1
            
            # Generate payload summary
            payload_summary = self._summarize_payload(entry.payload, event_type)
            
            events.append(TimelineEvent(
                seq=entry.seq,
                event_id=entry.event_id,
                event_type=event_type,
                timestamp=entry.timestamp,
                agent_id=None,  # Extract from payload if present
                node_name=entry.payload.get("node") if entry.payload else None,
                tool_name=entry.payload.get("tool") if entry.payload else None,
                payload_summary=payload_summary,
                payload_hash=entry.payload_hash,
                entry_hash=entry.entry_hash,
                prev_hash=entry.prev_hash,
                is_error=is_error,
                is_delegation=is_delegation,
            ))
        
        first_event = events[0].timestamp if events else None
        last_event = events[-1].timestamp if events else None
        
        return TimelineView(
            run_id=self.proof.header.run_id,
            total_events=len(events),
            events=events,
            first_event_at=first_event,
            last_event_at=last_event,
            error_count=error_count,
            delegation_count=delegation_count,
        )
    
    def get_lineage(self) -> LineageView:
        """Generate View 3: Lineage / Tree View."""
        header = self.proof.header
        
        # Create root node
        root = LineageNode(
            run_id=header.run_id,
            agent_id=header.agent_id,
            runtime=header.runtime,
            status=header.status.value if hasattr(header.status, 'value') else str(header.status),
            started_at=header.started_at,
            ended_at=header.ended_at,
            proof_id=header.proof_id,
            proof_verified=self._verification.valid,
            parent_run_id=header.parent_run_id,
            depth=0,
        )
        
        # TODO: Load child proofs and build tree
        # For now, just return the single root
        
        return LineageView(
            root=root,
            total_runs=1,
            max_depth=0,
            total_delegations=0,
            verified_proofs=1 if self._verification.valid else 0,
            pending_proofs=0,
        )
    
    def get_report(self) -> ReportView:
        """Generate View 4: Verification Report."""
        checks = []
        passed = 0
        failed = 0
        skipped = 0
        
        # Convert verification checks
        for check in self._verification.checks:
            status = CheckStatus.PASSED if check.passed else CheckStatus.FAILED
            if status == CheckStatus.PASSED:
                passed += 1
            else:
                failed += 1
            
            checks.append(VerificationCheck(
                name=check.name,
                status=status,
                message=check.message,
                details=check.details,
            ))
        
        # Generate human summary
        human_summary = self._generate_human_summary()
        
        # Get technical details
        commitments = self.proof.commitments
        
        return ReportView(
            proof_id=self.proof.header.proof_id,
            overall_status=VerificationStatus.VERIFIED if self._verification.valid else VerificationStatus.INVALID,
            verified_at=datetime.now(timezone.utc),
            checks=checks,
            passed_count=passed,
            failed_count=failed,
            skipped_count=skipped,
            human_summary=human_summary,
            proof_hash=commitments.proof_hash if commitments else None,
            event_root=commitments.event_root if commitments else None,
            signature_algorithm=commitments.signature.algorithm.value if commitments and commitments.signature else None,
        )
    
    def get_full_response(self) -> FullVerificationResponse:
        """Generate all 4 views."""
        return FullVerificationResponse(
            summary=self.get_summary(),
            timeline=self.get_timeline(),
            lineage=self.get_lineage(),
            report=self.get_report(),
        )
    
    def _generate_status_message(self) -> str:
        """Generate human-readable status message."""
        if self._verification.valid:
            return "This RunProof has been verified. The execution trace is authentic and untampered."
        else:
            errors = self._verification.errors[:3]  # First 3 errors
            return f"Verification failed: {'; '.join(errors)}"
    
    def _generate_human_summary(self) -> str:
        """Generate human-friendly summary for the report."""
        if self._verification.valid:
            lines = [
                "✅ This proof is valid.",
                "",
                "What this means:",
                "• The execution trace has not been altered",
                "• The proof was signed by a trusted runtime identity",
                f"• All {len(self.proof.trace)} events are cryptographically linked",
            ]
            
            if self.proof.header.parent_run_id:
                lines.append("• This is a child run of a parent workflow")
            
            return "\n".join(lines)
        else:
            lines = [
                "❌ This proof failed verification.",
                "",
                "Issues found:",
            ]
            for error in self._verification.errors[:5]:
                lines.append(f"• {error}")
            
            return "\n".join(lines)
    
    def _summarize_payload(self, payload: dict | None, event_type: str) -> str:
        """Generate human-readable payload summary."""
        if not payload:
            return event_type.replace("_", " ").title()
        
        # Common patterns
        if "node" in payload:
            return f"Node: {payload['node']}"
        if "tool" in payload:
            return f"Tool: {payload['tool']}"
        if "agent_id" in payload:
            return f"Agent: {payload['agent_id']}"
        if "status" in payload:
            return f"Status: {payload['status']}"
        if "error" in payload:
            return f"Error: {payload['error'][:50]}..."
        
        return event_type.replace("_", " ").title()
