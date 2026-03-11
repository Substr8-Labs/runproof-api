"""
Substr8 Verify API - Backend for RunProof verification UI.

Provides endpoints for the 4 verification views:
- Summary: The "green tick" page
- Timeline: Chronological events
- Lineage: Parent/child tree
- Report: Audit checks
"""

__version__ = "0.1.0"

from .app import app
from .schemas import (
    SummaryView,
    TimelineView,
    LineageView,
    ReportView,
    FullVerificationResponse,
)
from .service import ProofViewService

__all__ = [
    "__version__",
    "app",
    "SummaryView",
    "TimelineView",
    "LineageView",
    "ReportView",
    "FullVerificationResponse",
    "ProofViewService",
]
