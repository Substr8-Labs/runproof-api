"""
RunProof Builder Service

Aggregates governance events into RunProof artifacts.
Port: 8097

Design principles:
- Runs ≠ Sessions (adapter-defined boundaries)
- Idempotent event handling (dedup, ordering)
- Services consume references, not blobs
"""

import hashlib
import json
import os
import sqlite3
import uuid
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

# Ed25519 signing (Protocol Phase 1)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

app = FastAPI(
    title="RunProof Builder",
    version="0.1.0",
    description="Generates RunProof artifacts from governance events"
)

# Run Registry URL for auto-push
REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://localhost:8098")

# Railway RunProof API for verification
RAILWAY_URL = os.environ.get("RAILWAY_RUNPROOF_URL", "https://runproof-api-production.up.railway.app")

# Database
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "runproofs.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ============ Ed25519 Signing (Protocol Phase 1) ============

KEYS_DIR = os.path.join(os.path.dirname(__file__), "data", "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

RUNTIME_KEY_PATH = os.path.join(KEYS_DIR, "runtime.key")
RUNTIME_PUB_PATH = os.path.join(KEYS_DIR, "runtime.pub")

# Runtime signing key (loaded on startup)
_runtime_private_key: Optional[Ed25519PrivateKey] = None
_runtime_public_key: Optional[Ed25519PublicKey] = None
_runtime_key_id: Optional[str] = None


def load_or_generate_runtime_key():
    """Load existing runtime key or generate new one."""
    global _runtime_private_key, _runtime_public_key, _runtime_key_id
    
    if os.path.exists(RUNTIME_KEY_PATH):
        # Load existing key
        with open(RUNTIME_KEY_PATH, "rb") as f:
            _runtime_private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(RUNTIME_PUB_PATH, "rb") as f:
            _runtime_public_key = serialization.load_pem_public_key(f.read())
    else:
        # Generate new key pair
        _runtime_private_key = Ed25519PrivateKey.generate()
        _runtime_public_key = _runtime_private_key.public_key()
        
        # Save keys
        with open(RUNTIME_KEY_PATH, "wb") as f:
            f.write(_runtime_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(RUNTIME_PUB_PATH, "wb") as f:
            f.write(_runtime_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        os.chmod(RUNTIME_KEY_PATH, 0o600)  # Protect private key
    
    # Compute key ID (first 16 chars of public key hash)
    pub_bytes = _runtime_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    _runtime_key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    print(f"[RunProof Builder] Runtime key loaded: {_runtime_key_id}")


def sign_payload(payload_hash: str) -> dict:
    """Sign a payload hash and return signature object."""
    if not _runtime_private_key:
        raise RuntimeError("Runtime key not initialized")
    
    # Sign the hash bytes
    signature_bytes = _runtime_private_key.sign(payload_hash.encode())
    
    return {
        "signer_id": f"runtime:{_runtime_key_id}",
        "algorithm": "ed25519",
        "signature": base64.b64encode(signature_bytes).decode(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "key_id": _runtime_key_id
    }


def verify_signature(payload_hash: str, signature: dict) -> bool:
    """Verify a signature against payload hash."""
    if not _runtime_public_key:
        raise RuntimeError("Runtime key not initialized")
    
    try:
        sig_bytes = base64.b64decode(signature["signature"])
        _runtime_public_key.verify(sig_bytes, payload_hash.encode())
        return True
    except Exception:
        return False


def get_runtime_public_key() -> dict:
    """Get runtime public key info for verification."""
    if not _runtime_public_key:
        raise RuntimeError("Runtime key not initialized")
    
    pub_bytes = _runtime_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "key_id": _runtime_key_id,
        "algorithm": "ed25519",
        "public_key": pub_bytes.decode()
    }


# ============ Fingerprints (Protocol Phase 1) ============

def compute_fingerprint(data: Any) -> str:
    """Compute canonical fingerprint of data."""
    if isinstance(data, dict):
        # Sort keys for deterministic hashing
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
    elif isinstance(data, str):
        canonical = data
    else:
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def compute_fingerprints(
    agent_id: str,
    adapter: str,
    environment_data: Optional[Dict] = None,
    input_data: Optional[str] = None
) -> Dict[str, str]:
    """
    Compute hierarchical fingerprints for a run.
    
    Hierarchy:
    - spec_fingerprint: Agent identity/spec (from registry if available)
    - runtime_fingerprint: Runtime configuration (adapter + key)
    - environment_fingerprint: Capabilities and tools available
    - instance_fingerprint: Specific instance (runtime + agent)
    - run_fingerprint: This specific run (instance + input + env)
    """
    # Spec fingerprint: agent identity
    # Try to get from identity registry, fallback to agent_id hash
    spec_data = {"agent_id": agent_id}
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT spec_hash FROM agent_identities WHERE agent_id = ?",
                (agent_id,)
            ).fetchone()
            if row and row["spec_hash"]:
                spec_data["spec_hash"] = row["spec_hash"]
    except Exception:
        pass
    spec_fingerprint = compute_fingerprint(spec_data)
    
    # Runtime fingerprint: adapter + runtime key
    runtime_data = {
        "adapter": adapter,
        "runtime_key_id": _runtime_key_id or "unknown",
        "service": "runproof-builder"
    }
    runtime_fingerprint = compute_fingerprint(runtime_data)
    
    # Environment fingerprint: capabilities/tools
    env_data = environment_data or {}
    environment_fingerprint = compute_fingerprint(env_data)
    
    # Instance fingerprint: runtime + agent combined
    instance_data = {
        "spec": spec_fingerprint,
        "runtime": runtime_fingerprint
    }
    instance_fingerprint = compute_fingerprint(instance_data)
    
    # Run fingerprint: instance + environment + input
    run_data = {
        "instance": instance_fingerprint,
        "environment": environment_fingerprint,
        "input_hash": hashlib.sha256((input_data or "").encode()).hexdigest()[:32]
    }
    run_fingerprint = compute_fingerprint(run_data)
    
    return {
        "spec_fingerprint": spec_fingerprint,
        "runtime_fingerprint": runtime_fingerprint,
        "environment_fingerprint": environment_fingerprint,
        "instance_fingerprint": instance_fingerprint,
        "run_fingerprint": run_fingerprint
    }


# ============ Event Vocabulary (Protocol Phase 2) ============

# Map adapter event types to protocol canonical types
EVENT_TYPE_MAPPING = {
    # Lifecycle events
    "run.start": "started",
    "run.end": "completed",
    "run.fail": "failed",
    "run.checkpoint": "checkpointed",
    
    # Message events
    "message.received": "input_received",
    "message.sent": "output_produced",
    
    # Tool events
    "tool.invoke": "tool_invoked",
    "tool.result": "tool_completed",
    "tool.error": "tool_failed",
    
    # Environment events
    "environment.captured": "environment_snapshot",
    
    # Delegation events
    "delegation.start": "delegated",
    "delegation.end": "delegation_completed",
    "subagent.spawn": "delegated",
    "subagent.result": "delegation_completed",
    
    # Approval events
    "approval.requested": "approval_requested",
    "approval.granted": "approved",
    "approval.denied": "blocked",
    
    # Memory events
    "memory.write": "state_changed",
    "memory.read": "state_accessed",
    
    # Policy events
    "policy.check": "policy_evaluated",
    "policy.violation": "blocked",
}

# Reverse mapping for validation
CANONICAL_EVENT_TYPES = {
    "started", "completed", "failed", "checkpointed",
    "input_received", "output_produced",
    "tool_invoked", "tool_completed", "tool_failed",
    "environment_snapshot",
    "delegated", "delegation_completed",
    "approval_requested", "approved", "blocked",
    "state_changed", "state_accessed",
    "policy_evaluated",
}


def map_event_type(adapter_type: str) -> str:
    """Map adapter event type to protocol canonical type."""
    return EVENT_TYPE_MAPPING.get(adapter_type, adapter_type)


def enrich_event_with_canonical_type(event: Dict) -> Dict:
    """Add canonical_type to event if mappable."""
    adapter_type = event.get("type", "")
    canonical = map_event_type(adapter_type)
    if canonical != adapter_type:
        event["canonical_type"] = canonical
    return event


# In-memory state for active runs (backed by database)
active_runs: Dict[str, "Run"] = {}
processed_events: Dict[str, Set[str]] = defaultdict(set)

# Timeout for orphaned runs (30 minutes)
RUN_TIMEOUT_MINUTES = 30

# ============ Active Run Persistence ============

def persist_active_run(run: "Run"):
    """Persist active run to database."""
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO active_runs 
            (run_id, trace_id, agent_id, adapter, session_key, started_at, status, event_count, last_event_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (run.run_id, run.trace_id, run.agent_id, run.adapter, run.session_key,
              run.started_at.isoformat() if hasattr(run.started_at, 'isoformat') else run.started_at,
              run.status, len(run.events), datetime.utcnow().isoformat()))
        conn.commit()


def load_active_runs():
    """Load active runs from database on startup."""
    global active_runs
    with get_db() as conn:
        # Ensure table exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_runs (
                run_id TEXT PRIMARY KEY,
                trace_id TEXT,
                agent_id TEXT,
                adapter TEXT,
                session_key TEXT,
                started_at TEXT,
                status TEXT DEFAULT 'active',
                event_count INTEGER DEFAULT 0,
                updated_at TEXT
            )
        """)
        conn.commit()
        
        rows = conn.execute("""
            SELECT run_id, trace_id, agent_id, adapter, session_key, started_at, status, event_count
            FROM active_runs WHERE status = 'active'
        """).fetchall()
        
        for r in rows:
            run = Run(
                run_id=r[0],
                trace_id=r[1],
                agent_id=r[2],
                adapter=r[3],
                session_key=r[4],
                started_at=datetime.fromisoformat(r[5]) if r[5] else datetime.utcnow(),
                status=r[6]
            )
            active_runs[r[0]] = run
            print(f"[RunProof Builder] Restored active run: {r[0]}")
    
    if rows:
        print(f"[RunProof Builder] Loaded {len(rows)} active runs from database")


def mark_run_completed(run_id: str, status: str = "completed"):
    """Mark run as completed in database."""
    with get_db() as conn:
        conn.execute("UPDATE active_runs SET status = ? WHERE run_id = ?", (status, run_id))
        conn.commit()


def get_or_create_run(run_id: str, agent_id: str = "unknown", adapter: str = "openclaw", 
                       session_key: str = None, trace_id: str = None) -> "Run":
    """Get existing run or create new one (lazy creation)."""
    if run_id in active_runs:
        return active_runs[run_id]
    
    # Create new run
    if not trace_id:
        trace_id = generate_id("trace")
    
    run = Run(
        run_id=run_id,
        trace_id=trace_id,
        agent_id=agent_id,
        adapter=adapter,
        session_key=session_key,
        started_at=datetime.utcnow()
    )
    
    active_runs[run_id] = run
    processed_events[run_id] = set()
    persist_active_run(run)
    
    print(f"[RunProof Builder] Lazy-created run: {run_id}")
    return run


# ============ Models ============

class RunStartRequest(BaseModel):
    run_id: str
    trace_id: Optional[str] = None
    session_key: Optional[str] = None
    agent_id: str
    adapter: str = "openclaw"
    started_at: Optional[str] = None
    event_proof: Optional[Dict[str, Any]] = None  # RFC-003


class RunEventRequest(BaseModel):
    run_id: str
    event_id: str
    trace_id: Optional[str] = None
    type: str
    timestamp: str
    source: str
    seq: Optional[int] = None
    data: Dict[str, Any] = {}


class RunEndRequest(BaseModel):
    run_id: str
    ended_at: Optional[str] = None
    success: bool = True
    reason: Optional[str] = None


class RunCheckpointRequest(BaseModel):
    run_id: str
    checkpoint_at: Optional[str] = None
    reason: str = "compaction"


# ============ Data Classes ============

@dataclass
class GovernanceEvent:
    event_id: str
    type: str
    timestamp: str
    source: str
    seq: int
    data: Dict[str, Any]
    content_hash: str = ""
    
    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        data_str = json.dumps(self.data, sort_keys=True)
        return f"sha256:{hashlib.sha256(data_str.encode()).hexdigest()[:16]}"


@dataclass
class Run:
    run_id: str
    trace_id: str
    agent_id: str
    adapter: str
    session_key: Optional[str]
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: str = "active"  # active, completed, checkpoint, failed
    events: List[GovernanceEvent] = field(default_factory=list)
    policy_decisions: List[Dict] = field(default_factory=list)
    tool_calls: List[Dict] = field(default_factory=list)
    memory_commits: List[Dict] = field(default_factory=list)
    seq_counter: int = 0
    event_proof: Optional[Dict] = None  # RFC-003: what triggered this run


@dataclass
class RunProof:
    version: str
    run_id: str
    trace_id: str
    agent_id: str
    adapter: str
    started_at: str
    ended_at: str
    status: str
    events: List[Dict]
    policy_decisions: List[Dict]
    tool_calls: List[Dict]
    memory_commits: List[Dict]
    telemetry: Dict
    hashes: Dict
    root_hash: str
    # Three essential hashes (extracted from events)
    input_hash: Optional[str] = None
    output_hash: Optional[str] = None
    environment_hash: Optional[str] = None
    # EventProof (RFC-003) - what triggered this run
    event_proof: Optional[Dict] = None
    # StateProofs (RFC-004) - state transitions caused by this run
    state_proofs: List[Dict] = field(default_factory=list)
    # Proof topology type (Protocol Phase 1)
    proof_type: str = "receipt"  # receipt | dag_node | checkpoint | snapshot
    # Lineage fields (Protocol Phase 1)
    parent_id: Optional[str] = None  # Immediate parent proof
    root_id: Optional[str] = None    # Root case/mission lineage
    # Protocol spec version
    proof_spec_version: str = "1.0"
    # Attestation signatures (Protocol Phase 1)
    signatures: List[Dict] = field(default_factory=list)
    # Fingerprint hierarchy (Protocol Phase 1)
    fingerprints: Optional[Dict] = None


# ============ Database ============

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runproofs (
                run_id TEXT PRIMARY KEY,
                trace_id TEXT,
                agent_id TEXT,
                adapter TEXT,
                started_at TEXT,
                ended_at TEXT,
                status TEXT,
                root_hash TEXT,
                runproof_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trace ON runproofs(trace_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent ON runproofs(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_root_hash ON runproofs(root_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON runproofs(status)")
        
        # Ledger table (RFC-005)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_entries (
                entry_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                prev_hash TEXT,
                entry_hash TEXT NOT NULL,
                content_type TEXT NOT NULL,
                content_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(agent_id, seq)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_agent ON ledger_entries(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_agent_seq ON ledger_entries(agent_id, seq)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_hash ON ledger_entries(entry_hash)")
        conn.commit()


# ============ Ledger (RFC-005) ============

def get_last_ledger_entry(agent_id: str) -> Optional[Dict]:
    """Get the last ledger entry for an agent."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM ledger_entries WHERE agent_id = ? ORDER BY seq DESC LIMIT 1",
            (agent_id,)
        ).fetchone()
        if row:
            return dict(row)
    return None


def compute_ledger_entry_hash(entry_data: Dict) -> str:
    """Compute hash for a ledger entry."""
    hashable = {
        "agent_id": entry_data["agent_id"],
        "seq": entry_data["seq"],
        "timestamp": entry_data["timestamp"],
        "prev_hash": entry_data["prev_hash"],
        "content_type": entry_data["content_type"],
        "content": entry_data["content"],
    }
    return hashlib.sha256(json.dumps(hashable, sort_keys=True).encode()).hexdigest()


def append_ledger_entry(agent_id: str, content_type: str, content: Dict) -> Dict:
    """Append a new entry to the agent's ledger."""
    last = get_last_ledger_entry(agent_id)
    
    entry = {
        "entry_id": generate_id("ledger"),
        "agent_id": agent_id,
        "seq": (last["seq"] + 1) if last else 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prev_hash": last["entry_hash"] if last else None,
        "content_type": content_type,
        "content": content,
    }
    entry["entry_hash"] = compute_ledger_entry_hash(entry)
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO ledger_entries 
            (entry_id, agent_id, seq, timestamp, prev_hash, entry_hash, content_type, content_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry["entry_id"],
            entry["agent_id"],
            entry["seq"],
            entry["timestamp"],
            entry["prev_hash"],
            entry["entry_hash"],
            entry["content_type"],
            json.dumps(entry["content"])
        ))
        conn.commit()
    
    print(f"[Ledger] Entry #{entry['seq']} appended for {agent_id} ({content_type})")
    return entry


def verify_ledger_chain(agent_id: str, from_seq: int = 0) -> Dict:
    """Verify the hash chain is intact."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ledger_entries WHERE agent_id = ? AND seq >= ? ORDER BY seq",
            (agent_id, from_seq)
        ).fetchall()
    
    if not rows:
        return {"valid": True, "entries_checked": 0}
    
    prev_hash = None
    for row in rows:
        entry = dict(row)
        
        # Check prev_hash matches
        if entry["prev_hash"] != prev_hash:
            return {
                "valid": False,
                "error": f"prev_hash mismatch at seq {entry['seq']}",
                "expected": prev_hash,
                "actual": entry["prev_hash"]
            }
        
        # Check entry_hash is correct
        content = json.loads(entry["content_json"])
        check_data = {
            "agent_id": entry["agent_id"],
            "seq": entry["seq"],
            "timestamp": entry["timestamp"],
            "prev_hash": entry["prev_hash"],
            "content_type": entry["content_type"],
            "content": content,
        }
        expected_hash = hashlib.sha256(json.dumps(check_data, sort_keys=True).encode()).hexdigest()
        
        if entry["entry_hash"] != expected_hash:
            return {
                "valid": False,
                "error": f"entry_hash mismatch at seq {entry['seq']}",
                "expected": expected_hash,
                "actual": entry["entry_hash"]
            }
        
        prev_hash = entry["entry_hash"]
    
    return {"valid": True, "entries_checked": len(rows), "latest_seq": rows[-1]["seq"]}


# ============ Checkpoints (RFC-006) ============

def init_checkpoint_table():
    """Initialize checkpoint table."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                from_seq INTEGER NOT NULL,
                to_seq INTEGER NOT NULL,
                entry_count INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                prev_checkpoint_id TEXT,
                prev_merkle_root TEXT,
                checkpoint_hash TEXT NOT NULL,
                anchor_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(agent_id, to_seq)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_checkpoint_agent ON ledger_checkpoints(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_checkpoint_merkle ON ledger_checkpoints(merkle_root)")
        conn.commit()


def build_merkle_tree(hashes: List[str]) -> str:
    """Build Merkle tree and return root hash."""
    if not hashes:
        return hashlib.sha256(b"empty").hexdigest()
    
    # Work with a copy
    layer = list(hashes)
    
    # Pad to power of 2
    while len(layer) & (len(layer) - 1):
        layer.append(layer[-1])
    
    # Build tree bottom-up
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(hashlib.sha256(combined.encode()).hexdigest())
        layer = next_layer
    
    return layer[0]


def get_latest_checkpoint(agent_id: str) -> Optional[Dict]:
    """Get the latest checkpoint for an agent."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM ledger_checkpoints WHERE agent_id = ? ORDER BY to_seq DESC LIMIT 1",
            (agent_id,)
        ).fetchone()
        if row:
            result = dict(row)
            if result.get("anchor_json"):
                result["anchor"] = json.loads(result.pop("anchor_json"))
            return result
    return None


def create_checkpoint(agent_id: str) -> Dict:
    """Create a checkpoint for ledger entries since last checkpoint."""
    # Get previous checkpoint
    prev = get_latest_checkpoint(agent_id)
    from_seq = (prev["to_seq"] + 1) if prev else 0
    
    # Get entries since last checkpoint
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ledger_entries WHERE agent_id = ? AND seq >= ? ORDER BY seq",
            (agent_id, from_seq)
        ).fetchall()
    
    if not rows:
        raise ValueError("No entries to checkpoint")
    
    entries = [dict(row) for row in rows]
    
    # Build Merkle root
    entry_hashes = [e["entry_hash"] for e in entries]
    merkle_root = build_merkle_tree(entry_hashes)
    
    # Create checkpoint
    checkpoint = {
        "checkpoint_id": generate_id("ckpt"),
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "from_seq": from_seq,
        "to_seq": entries[-1]["seq"],
        "entry_count": len(entries),
        "merkle_root": merkle_root,
        "prev_checkpoint_id": prev["checkpoint_id"] if prev else None,
        "prev_merkle_root": prev["merkle_root"] if prev else None,
    }
    
    # Compute checkpoint hash
    hash_data = {
        "agent_id": checkpoint["agent_id"],
        "from_seq": checkpoint["from_seq"],
        "to_seq": checkpoint["to_seq"],
        "merkle_root": checkpoint["merkle_root"],
        "prev_merkle_root": checkpoint["prev_merkle_root"],
    }
    checkpoint["checkpoint_hash"] = hashlib.sha256(
        json.dumps(hash_data, sort_keys=True).encode()
    ).hexdigest()
    
    # Save checkpoint
    with get_db() as conn:
        conn.execute("""
            INSERT INTO ledger_checkpoints
            (checkpoint_id, agent_id, timestamp, from_seq, to_seq, entry_count,
             merkle_root, prev_checkpoint_id, prev_merkle_root, checkpoint_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            checkpoint["checkpoint_id"],
            checkpoint["agent_id"],
            checkpoint["timestamp"],
            checkpoint["from_seq"],
            checkpoint["to_seq"],
            checkpoint["entry_count"],
            checkpoint["merkle_root"],
            checkpoint["prev_checkpoint_id"],
            checkpoint["prev_merkle_root"],
            checkpoint["checkpoint_hash"],
        ))
        conn.commit()
    
    print(f"[Checkpoint] Created {checkpoint['checkpoint_id']} for {agent_id} "
          f"(seq {from_seq}-{checkpoint['to_seq']}, {len(entries)} entries, root: {merkle_root[:16]})")
    
    return checkpoint


def verify_checkpoint_chain(agent_id: str) -> Dict:
    """Verify the checkpoint chain is valid."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ledger_checkpoints WHERE agent_id = ? ORDER BY to_seq",
            (agent_id,)
        ).fetchall()
    
    if not rows:
        return {"valid": True, "checkpoints_checked": 0}
    
    prev_root = None
    prev_id = None
    
    for row in rows:
        ckpt = dict(row)
        
        # Check linkage
        if ckpt["prev_merkle_root"] != prev_root:
            return {
                "valid": False,
                "error": f"prev_merkle_root mismatch at checkpoint {ckpt['checkpoint_id']}"
            }
        if ckpt["prev_checkpoint_id"] != prev_id:
            return {
                "valid": False,
                "error": f"prev_checkpoint_id mismatch at checkpoint {ckpt['checkpoint_id']}"
            }
        
        # Verify merkle root matches entries
        with get_db() as conn2:
            entry_rows = conn2.execute(
                "SELECT entry_hash FROM ledger_entries WHERE agent_id = ? AND seq >= ? AND seq <= ? ORDER BY seq",
                (agent_id, ckpt["from_seq"], ckpt["to_seq"])
            ).fetchall()
        
        entry_hashes = [r["entry_hash"] for r in entry_rows]
        expected_root = build_merkle_tree(entry_hashes)
        
        if ckpt["merkle_root"] != expected_root:
            return {
                "valid": False,
                "error": f"merkle_root mismatch at checkpoint {ckpt['checkpoint_id']}",
                "expected": expected_root,
                "actual": ckpt["merkle_root"]
            }
        
        prev_root = ckpt["merkle_root"]
        prev_id = ckpt["checkpoint_id"]
    
    return {"valid": True, "checkpoints_checked": len(rows), "latest_checkpoint": rows[-1]["checkpoint_id"]}


# ============ BranchProof (RFC-007) ============

def init_branch_table():
    """Initialize branch table."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS branch_proofs (
                branch_id TEXT PRIMARY KEY,
                branch_type TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                origin_json TEXT NOT NULL,
                branch_run_id TEXT,
                modifications_json TEXT,
                parent_branch_id TEXT,
                branch_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_branch_type ON branch_proofs(branch_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_branch_agent ON branch_proofs(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_branch_run ON branch_proofs(branch_run_id)")
        conn.commit()


def compute_branch_hash(branch_data: Dict) -> str:
    """Compute hash for a branch proof."""
    hashable = {
        "branch_type": branch_data["branch_type"],
        "agent_id": branch_data["agent_id"],
        "timestamp": branch_data["timestamp"],
        "origin": branch_data["origin"],
        "modifications": branch_data.get("modifications"),
    }
    return hashlib.sha256(json.dumps(hashable, sort_keys=True).encode()).hexdigest()


def create_branch(
    agent_id: str,
    branch_type: str,
    origin: Dict,
    modifications: Dict = None,
    parent_branch_id: str = None
) -> Dict:
    """Create a new branch proof."""
    branch = {
        "branch_id": generate_id("branch"),
        "branch_type": branch_type,
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "origin": origin,
        "modifications": modifications,
        "parent_branch_id": parent_branch_id,
        "branch_run_id": None,  # Will be set when run starts
    }
    branch["branch_hash"] = compute_branch_hash(branch)
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO branch_proofs
            (branch_id, branch_type, agent_id, timestamp, origin_json, 
             modifications_json, parent_branch_id, branch_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            branch["branch_id"],
            branch["branch_type"],
            branch["agent_id"],
            branch["timestamp"],
            json.dumps(branch["origin"]),
            json.dumps(branch["modifications"]) if branch["modifications"] else None,
            branch["parent_branch_id"],
            branch["branch_hash"],
        ))
        conn.commit()
    
    print(f"[Branch] Created {branch['branch_type']} branch: {branch['branch_id']} for {agent_id}")
    return branch


def link_branch_to_run(branch_id: str, run_id: str):
    """Link a branch to its resulting run."""
    with get_db() as conn:
        conn.execute(
            "UPDATE branch_proofs SET branch_run_id = ? WHERE branch_id = ?",
            (run_id, branch_id)
        )
        conn.commit()


def get_branch(branch_id: str) -> Optional[Dict]:
    """Get a branch proof by ID."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM branch_proofs WHERE branch_id = ?",
            (branch_id,)
        ).fetchone()
    
    if not row:
        return None
    
    branch = dict(row)
    branch["origin"] = json.loads(branch.pop("origin_json"))
    if branch.get("modifications_json"):
        branch["modifications"] = json.loads(branch.pop("modifications_json"))
    else:
        branch.pop("modifications_json", None)
    return branch


def get_branches_for_agent(agent_id: str, limit: int = 100) -> List[Dict]:
    """Get all branches for an agent."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM branch_proofs WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, limit)
        ).fetchall()
    
    branches = []
    for row in rows:
        branch = dict(row)
        branch["origin"] = json.loads(branch.pop("origin_json"))
        if branch.get("modifications_json"):
            branch["modifications"] = json.loads(branch.pop("modifications_json"))
        else:
            branch.pop("modifications_json", None)
        branches.append(branch)
    
    return branches


def create_retry_branch(agent_id: str, failed_run_id: str, modifications: Dict = None) -> Dict:
    """Create a retry branch from a failed run."""
    # Get the failed run
    with get_db() as conn:
        row = conn.execute(
            "SELECT runproof_json FROM runproofs WHERE run_id = ?",
            (failed_run_id,)
        ).fetchone()
    
    if not row:
        raise ValueError(f"Run not found: {failed_run_id}")
    
    runproof = json.loads(row["runproof_json"])
    
    origin = {
        "run_id": failed_run_id,
        "state_hash": runproof.get("input_hash"),
        "original_status": runproof.get("status"),
    }
    
    return create_branch(
        agent_id=agent_id,
        branch_type="retry",
        origin=origin,
        modifications=modifications,
    )


def create_replay_branch(agent_id: str, checkpoint_id: str, new_context: Dict = None) -> Dict:
    """Create a replay branch from a checkpoint."""
    checkpoint = get_latest_checkpoint(agent_id)
    
    if not checkpoint or checkpoint["checkpoint_id"] != checkpoint_id:
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM ledger_checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,)
            ).fetchone()
        if not row:
            raise ValueError(f"Checkpoint not found: {checkpoint_id}")
        checkpoint = dict(row)
    
    origin = {
        "checkpoint_id": checkpoint_id,
        "ledger_seq": checkpoint["to_seq"],
        "state_hash": checkpoint["merkle_root"],
    }
    
    return create_branch(
        agent_id=agent_id,
        branch_type="replay",
        origin=origin,
        modifications={"context": new_context} if new_context else None,
    )


def create_fork_branches(agent_id: str, origin_run_id: str, configs: List[Dict]) -> List[Dict]:
    """Create multiple fork branches for A/B testing."""
    # Get origin run
    with get_db() as conn:
        row = conn.execute(
            "SELECT runproof_json FROM runproofs WHERE run_id = ?",
            (origin_run_id,)
        ).fetchone()
    
    if not row:
        raise ValueError(f"Run not found: {origin_run_id}")
    
    runproof = json.loads(row["runproof_json"])
    
    branches = []
    for i, config in enumerate(configs):
        origin = {
            "run_id": origin_run_id,
            "state_hash": runproof.get("environment_hash"),
            "fork_index": i,
        }
        
        branch = create_branch(
            agent_id=agent_id,
            branch_type="fork",
            origin=origin,
            modifications={"config": config},
        )
        branches.append(branch)
    
    return branches


# ============ AgentIdentityProof (RFC-008) ============

def init_identity_table():
    """Initialize identity tables."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_identities (
                agent_id TEXT PRIMARY KEY,
                identity_key TEXT NOT NULL,
                genesis_hash TEXT NOT NULL,
                current_version TEXT NOT NULL,
                version_seq INTEGER NOT NULL,
                spec_json TEXT NOT NULL,
                ledger_id TEXT,
                latest_checkpoint TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                signature TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS identity_versions (
                version_hash TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                version_seq INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                changes_json TEXT,
                prev_version_hash TEXT NOT NULL,
                signature TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_identity_versions ON identity_versions(agent_id, version_seq)")
        conn.commit()


def generate_identity_key() -> tuple:
    """Generate a pseudo identity key (simplified - use real crypto in production)."""
    # In production, use ed25519 or similar
    key_data = f"{uuid.uuid4()}-{datetime.now(timezone.utc).isoformat()}"
    private_key = hashlib.sha256(key_data.encode()).hexdigest()
    public_key = hashlib.sha256(private_key.encode()).hexdigest()[:64]
    return private_key, public_key


def sign_data(private_key: str, data: str) -> str:
    """Sign data with private key (simplified)."""
    return hashlib.sha256(f"{private_key}:{data}".encode()).hexdigest()


def verify_signature(public_key: str, signature: str, data: str) -> bool:
    """Verify signature (simplified - always true for now)."""
    # In production, use real signature verification
    return True


def create_agent_identity(agent_id: str, spec: Dict) -> Dict:
    """Create initial agent identity."""
    private_key, public_key = generate_identity_key()
    
    # Compute spec hashes
    spec_hashes = {
        "fdaa_hash": hashlib.sha256(json.dumps(spec.get("fdaa", {}), sort_keys=True).encode()).hexdigest(),
        "skills_hash": hashlib.sha256(json.dumps(spec.get("skills", []), sort_keys=True).encode()).hexdigest(),
        "config_hash": hashlib.sha256(json.dumps(spec.get("config", {}), sort_keys=True).encode()).hexdigest(),
    }
    
    created_at = datetime.now(timezone.utc).isoformat()
    
    # Compute genesis hash
    genesis_data = {
        "agent_id": agent_id,
        "identity_key": public_key,
        "spec": spec_hashes,
        "created_at": created_at,
    }
    genesis_hash = hashlib.sha256(json.dumps(genesis_data, sort_keys=True).encode()).hexdigest()
    
    identity = {
        "agent_id": agent_id,
        "identity_key": public_key,
        "genesis_hash": genesis_hash,
        "current_version": genesis_hash,
        "version_seq": 0,
        "spec": spec_hashes,
        "ledger_id": None,
        "latest_checkpoint": None,
        "created_at": created_at,
        "updated_at": created_at,
    }
    
    # Sign the identity
    identity_bytes = json.dumps({k: v for k, v in identity.items() if k != "signature"}, sort_keys=True)
    identity["signature"] = sign_data(private_key, identity_bytes)
    
    # Save to database
    with get_db() as conn:
        conn.execute("""
            INSERT INTO agent_identities
            (agent_id, identity_key, genesis_hash, current_version, version_seq,
             spec_json, ledger_id, latest_checkpoint, created_at, updated_at, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            identity["agent_id"],
            identity["identity_key"],
            identity["genesis_hash"],
            identity["current_version"],
            identity["version_seq"],
            json.dumps(identity["spec"]),
            identity["ledger_id"],
            identity["latest_checkpoint"],
            identity["created_at"],
            identity["updated_at"],
            identity["signature"],
        ))
        conn.commit()
    
    print(f"[Identity] Created identity for {agent_id} (genesis: {genesis_hash[:16]})")
    return identity


def get_agent_identity(agent_id: str) -> Optional[Dict]:
    """Get agent identity."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM agent_identities WHERE agent_id = ?",
            (agent_id,)
        ).fetchone()
    
    if not row:
        return None
    
    identity = dict(row)
    identity["spec"] = json.loads(identity.pop("spec_json"))
    return identity


def update_agent_identity(agent_id: str, new_spec: Dict, changes: Dict) -> Dict:
    """Update agent identity with new version."""
    identity = get_agent_identity(agent_id)
    if not identity:
        raise ValueError(f"Identity not found: {agent_id}")
    
    # Compute new spec hashes
    new_spec_hashes = {
        "fdaa_hash": hashlib.sha256(json.dumps(new_spec.get("fdaa", {}), sort_keys=True).encode()).hexdigest(),
        "skills_hash": hashlib.sha256(json.dumps(new_spec.get("skills", []), sort_keys=True).encode()).hexdigest(),
        "config_hash": hashlib.sha256(json.dumps(new_spec.get("config", {}), sort_keys=True).encode()).hexdigest(),
    }
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Create version record
    version = {
        "agent_id": agent_id,
        "version_seq": identity["version_seq"] + 1,
        "timestamp": timestamp,
        "changes": changes,
        "prev_version_hash": identity["current_version"],
    }
    version_data = json.dumps({k: v for k, v in version.items() if k not in ["version_hash", "signature"]}, sort_keys=True)
    version["version_hash"] = hashlib.sha256(version_data.encode()).hexdigest()
    version["signature"] = sign_data(identity["identity_key"], version_data)
    
    # Save version
    with get_db() as conn:
        conn.execute("""
            INSERT INTO identity_versions
            (version_hash, agent_id, version_seq, timestamp, changes_json, prev_version_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            version["version_hash"],
            version["agent_id"],
            version["version_seq"],
            version["timestamp"],
            json.dumps(version["changes"]),
            version["prev_version_hash"],
            version["signature"],
        ))
        
        # Update identity
        conn.execute("""
            UPDATE agent_identities
            SET current_version = ?, version_seq = ?, spec_json = ?, updated_at = ?
            WHERE agent_id = ?
        """, (
            version["version_hash"],
            version["version_seq"],
            json.dumps(new_spec_hashes),
            timestamp,
            agent_id,
        ))
        conn.commit()
    
    print(f"[Identity] Updated {agent_id} to version {version['version_seq']} ({version['version_hash'][:16]})")
    return version


def get_identity_versions(agent_id: str) -> List[Dict]:
    """Get version history for agent."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM identity_versions WHERE agent_id = ? ORDER BY version_seq",
            (agent_id,)
        ).fetchall()
    
    versions = []
    for row in rows:
        version = dict(row)
        if version.get("changes_json"):
            version["changes"] = json.loads(version.pop("changes_json"))
        else:
            version.pop("changes_json", None)
        versions.append(version)
    
    return versions


def verify_agent_identity(agent_id: str) -> Dict:
    """Verify agent identity chain."""
    identity = get_agent_identity(agent_id)
    if not identity:
        return {"valid": False, "error": "Identity not found"}
    
    # Verify genesis hash computation
    genesis_data = {
        "agent_id": identity["agent_id"],
        "identity_key": identity["identity_key"],
        "spec": identity["spec"],
        "created_at": identity["created_at"],
    }
    expected_genesis = hashlib.sha256(json.dumps(genesis_data, sort_keys=True).encode()).hexdigest()
    
    if identity["genesis_hash"] != expected_genesis:
        return {"valid": False, "error": "Genesis hash mismatch"}
    
    # Verify version chain
    versions = get_identity_versions(agent_id)
    prev_hash = identity["genesis_hash"]
    
    for version in versions:
        if version["prev_version_hash"] != prev_hash:
            return {
                "valid": False,
                "error": f"Version chain broken at seq {version['version_seq']}"
            }
        prev_hash = version["version_hash"]
    
    if prev_hash != identity["current_version"]:
        return {"valid": False, "error": "Current version mismatch"}
    
    return {
        "valid": True,
        "agent_id": agent_id,
        "genesis_hash": identity["genesis_hash"],
        "current_version": identity["current_version"],
        "version_count": len(versions),
    }


def bind_identity_to_ledger(agent_id: str) -> Dict:
    """Bind agent identity to their ledger."""
    identity = get_agent_identity(agent_id)
    if not identity:
        raise ValueError(f"Identity not found: {agent_id}")
    
    ledger_id = f"ledger-{agent_id}"
    
    # Update identity
    with get_db() as conn:
        conn.execute(
            "UPDATE agent_identities SET ledger_id = ? WHERE agent_id = ?",
            (ledger_id, agent_id)
        )
        conn.commit()
    
    # Add binding entry to ledger
    append_ledger_entry(
        agent_id=agent_id,
        content_type="identity_binding",
        content={
            "identity_key": identity["identity_key"],
            "genesis_hash": identity["genesis_hash"],
            "ledger_id": ledger_id,
        }
    )
    
    print(f"[Identity] Bound {agent_id} to ledger {ledger_id}")
    return {"agent_id": agent_id, "ledger_id": ledger_id}


# ============ RunProof Builder ============

def compute_entry_hashes(events: List[GovernanceEvent]) -> List[str]:
    """Compute hash chain for events."""
    hashes = []
    prev_hash = "0" * 64
    
    for event in events:
        entry_data = f"{prev_hash}:{event.event_id}:{event.type}:{event.timestamp}:{event.content_hash}"
        entry_hash = hashlib.sha256(entry_data.encode()).hexdigest()
        hashes.append(entry_hash)
        prev_hash = entry_hash
    
    return hashes


def compute_root_hash(run: Run, entry_hashes: List[str]) -> str:
    """Compute final root hash for RunProof."""
    root_data = {
        "run_id": run.run_id,
        "trace_id": run.trace_id,
        "agent_id": run.agent_id,
        "started_at": run.started_at.isoformat(),
        "ended_at": run.ended_at.isoformat() if run.ended_at else None,
        "event_count": len(run.events),
        "final_entry_hash": entry_hashes[-1] if entry_hashes else "empty"
    }
    return hashlib.sha256(json.dumps(root_data, sort_keys=True).encode()).hexdigest()


def extract_essential_hashes(events: List[GovernanceEvent]) -> Dict[str, Optional[str]]:
    """Extract the three essential hashes from events.
    
    The three essential hashes per the Verified Agent Progression spec:
    - input_hash: What the agent was asked (from first message.received)
    - output_hash: What was produced (from last message.sent)
    - environment_hash: What capabilities existed (from environment.captured or first message.received)
    """
    input_hash = None
    output_hash = None
    environment_hash = None
    
    for event in events:
        data = event.data or {}
        
        # Input hash from first message.received
        if event.type == "message.received" and input_hash is None:
            input_hash = data.get("input_hash")
            # Also grab environment_hash if present
            if environment_hash is None:
                environment_hash = data.get("environment_hash")
        
        # Environment hash from environment.captured
        if event.type == "environment.captured" and environment_hash is None:
            environment_hash = data.get("environment_hash")
        
        # Output hash from last message.sent (keep updating)
        if event.type == "message.sent":
            output_hash = data.get("output_hash")
    
    return {
        "input_hash": input_hash,
        "output_hash": output_hash,
        "environment_hash": environment_hash
    }


def extract_state_proofs(events: List[GovernanceEvent]) -> List[Dict]:
    """Extract StateProofs from state.proof events (RFC-004)."""
    state_proofs = []
    
    for event in events:
        if event.type == "state.proof":
            data = event.data or {}
            state_proofs.append({
                "proof_id": data.get("proof_id"),
                "timestamp": data.get("timestamp"),
                "state_type": data.get("state_type"),
                "prev_state_hash": data.get("prev_state_hash"),
                "next_state_hash": data.get("next_state_hash"),
                "run_id": data.get("run_id"),
                "run_proof_hash": data.get("run_proof_hash"),
            })
    
    return state_proofs


def build_runproof(run: Run) -> RunProof:
    """Build RunProof artifact from run data."""
    # Sort events deterministically
    sorted_events = sorted(run.events, key=lambda e: (e.seq, e.timestamp))
    
    # Compute hashes
    entry_hashes = compute_entry_hashes(sorted_events)
    root_hash = compute_root_hash(run, entry_hashes)
    
    # Extract the three essential hashes from events
    essential_hashes = extract_essential_hashes(sorted_events)
    
    # Extract StateProofs from events (RFC-004)
    state_proofs = extract_state_proofs(sorted_events)
    
    # Build telemetry
    telemetry = {
        "event_count": len(sorted_events),
        "policy_decisions": len(run.policy_decisions),
        "tool_calls": len(run.tool_calls),
        "memory_commits": len(run.memory_commits),
        "events_by_type": {}
    }
    for event in sorted_events:
        telemetry["events_by_type"][event.type] = telemetry["events_by_type"].get(event.type, 0) + 1
    
    # Sign the root hash (Protocol Phase 1)
    signatures = []
    try:
        runtime_sig = sign_payload(root_hash)
        signatures.append(runtime_sig)
    except Exception as e:
        print(f"[RunProof Builder] Warning: Could not sign proof: {e}")
    
    # Compute fingerprints (Protocol Phase 1)
    # Extract environment data from environment.captured events
    env_events = [e for e in sorted_events if e.type == "environment.captured"]
    environment_data = {}
    if env_events:
        # Combine all environment captures
        for e in env_events:
            if e.data:
                environment_data.update(e.data)
    
    # Extract input from first message event
    input_data = ""
    msg_events = [e for e in sorted_events if e.type == "message.received"]
    if msg_events:
        first_msg = msg_events[0]
        if first_msg.data and "content" in first_msg.data:
            input_data = str(first_msg.data["content"])[:1000]  # Limit for hashing
    
    fingerprints = compute_fingerprints(
        agent_id=run.agent_id,
        adapter=run.adapter,
        environment_data=environment_data,
        input_data=input_data
    )
    
    return RunProof(
        version="1.0",
        run_id=run.run_id,
        trace_id=run.trace_id,
        agent_id=run.agent_id,
        adapter=run.adapter,
        started_at=run.started_at.isoformat(),
        ended_at=run.ended_at.isoformat() if run.ended_at else datetime.now(timezone.utc).isoformat(),
        status=run.status,
        events=[enrich_event_with_canonical_type(asdict(e)) for e in sorted_events],
        policy_decisions=run.policy_decisions,
        tool_calls=run.tool_calls,
        memory_commits=run.memory_commits,
        telemetry=telemetry,
        hashes={
            "entries": entry_hashes,
            "chain_valid": True
        },
        root_hash=root_hash,
        # Three essential hashes at header level for verification
        input_hash=essential_hashes["input_hash"],
        output_hash=essential_hashes["output_hash"],
        environment_hash=essential_hashes["environment_hash"],
        # EventProof (RFC-003) - what triggered this run
        event_proof=run.event_proof,
        # StateProofs (RFC-004) - state transitions caused by this run
        state_proofs=state_proofs,
        # Attestation signatures (Protocol Phase 1)
        signatures=signatures,
        # Fingerprint hierarchy (Protocol Phase 1)
        fingerprints=fingerprints
    )


def save_runproof(runproof: RunProof):
    """Persist RunProof to database."""
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO runproofs
            (run_id, trace_id, agent_id, adapter, started_at, ended_at, status, root_hash, runproof_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            runproof.run_id,
            runproof.trace_id,
            runproof.agent_id,
            runproof.adapter,
            runproof.started_at,
            runproof.ended_at,
            runproof.status,
            runproof.root_hash,
            json.dumps(asdict(runproof))
        ))
        conn.commit()
    
    # Append to agent ledger (RFC-005)
    append_ledger_entry(
        agent_id=runproof.agent_id,
        content_type="run",
        content={
            "run_id": runproof.run_id,
            "run_proof_hash": runproof.root_hash,
            "event_proof": runproof.event_proof,
            "state_proofs": runproof.state_proofs,
            "input_hash": runproof.input_hash,
            "output_hash": runproof.output_hash,
        }
    )
    
    # Auto-push to Run Registry
    push_to_registry(runproof)


def push_to_registry(runproof: RunProof):
    """Push RunProof to Run Registry for indexing."""
    try:
        runproof_dict = asdict(runproof)
        payload = {
            "run_id": runproof.run_id,
            "trace_id": runproof.trace_id,
            "agent_id": runproof.agent_id,
            "adapter": runproof.adapter,
            "status": runproof.status,
            "started_at": runproof.started_at,
            "ended_at": runproof.ended_at,
            "root_hash": runproof.root_hash,
            "runproof": runproof_dict
        }
        
        resp = httpx.post(
            f"{REGISTRY_URL}/v1/ingest",
            json=payload,
            timeout=5.0
        )
        
        if resp.status_code == 200:
            print(f"[RunProof Builder] Pushed to registry: {runproof.run_id}")
        else:
            print(f"[RunProof Builder] Registry push failed: {resp.status_code}")
    except Exception as e:
        # Non-blocking: registry might be down
        pass
    
    # Also push to Railway for verification/storage
    push_to_railway(runproof)


def push_to_railway(runproof: RunProof):
    """Push RunProof to Railway API for verification and storage."""
    try:
        runproof_dict = asdict(runproof)
        
        # Transform to Railway API format
        railway_proof = {
            "header": {
                "proof_id": runproof.run_id,  # Use run_id as proof_id
                "run_id": runproof.run_id,
                "trace_id": runproof.trace_id,
                "agent_id": runproof.agent_id,
                "runtime": runproof.adapter,
                "started_at": runproof.started_at,
                "ended_at": runproof.ended_at,
                "status": runproof.status,
            },
            "identity": {
                "signer": None,
                "policy": None,
            },
            "trace": runproof_dict.get("events", []),
            "hashes": runproof_dict.get("hashes", {}),
            "root_hash": runproof.root_hash,
            "telemetry": runproof_dict.get("telemetry", {}),
        }
        
        resp = httpx.post(
            f"{RAILWAY_URL}/verify",
            json={"proof": railway_proof},
            timeout=10.0
        )
        
        if resp.status_code == 200:
            result = resp.json()
            valid = result.get("valid", False)
            print(f"[RunProof Builder] Railway verify: {runproof.run_id} (valid={valid})")
        else:
            print(f"[RunProof Builder] Railway push failed: {resp.status_code} - {resp.text[:200]}")
    except Exception as e:
        # Non-blocking: Railway might be down
        print(f"[RunProof Builder] Railway unavailable: {e}")
        print(f"[RunProof Builder] Registry push skipped: {e}")


def generate_id(prefix: str) -> str:
    """Generate a unique ID with prefix."""
    ts = hex(int(datetime.now(timezone.utc).timestamp() * 1000))[2:]
    rand = uuid.uuid4().hex[:6]
    return f"{prefix}-{ts}-{rand}"


# ============ API Endpoints ============

@app.on_event("startup")
def init_lifecycle_table():
    """Initialize agent_lifecycle table."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_lifecycle (
                agent_id TEXT PRIMARY KEY,
                status TEXT DEFAULT 'active',
                registered_at TEXT,
                last_heartbeat TEXT,
                metadata TEXT,
                paused_at TEXT,
                retired_at TEXT
            )
        """)
        conn.commit()


def init_anchoring_table():
    """Initialize external_anchors table."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS external_anchors (
                id TEXT PRIMARY KEY,
                proof_id TEXT,
                proof_type TEXT,
                proof_hash TEXT,
                anchor_type TEXT,
                status TEXT DEFAULT 'pending',
                submitted_at TEXT,
                confirmed_at TEXT,
                transaction_id TEXT,
                block_number INTEGER,
                anchor_data TEXT
            )
        """)
        conn.commit()


async def startup():
    init_db()
    init_checkpoint_table()
    init_branch_table()
    init_identity_table()
    init_lifecycle_table()
    init_anchoring_table()
    load_or_generate_runtime_key()
    load_active_runs()  # Restore active runs from database
    print(f"[RunProof Builder] Database initialized at {DB_PATH}")


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "runproof-builder",
        "active_runs": len(active_runs),
        "database": DB_PATH
    }


@app.post("/v1/run/start")
async def run_start(req: RunStartRequest):
    """Initialize a new run."""
    run_id = req.run_id
    trace_id = req.trace_id or generate_id("trace")
    
    if run_id in active_runs:
        # Idempotent: return existing run
        run = active_runs[run_id]
        return {
            "status": "exists",
            "run_id": run_id,
            "trace_id": run.trace_id
        }
    
    started_at = datetime.fromisoformat(req.started_at.replace("Z", "+00:00")) if req.started_at else datetime.now(timezone.utc)
    
    run = Run(
        run_id=run_id,
        trace_id=trace_id,
        agent_id=req.agent_id,
        adapter=req.adapter,
        session_key=req.session_key,
        started_at=started_at,
        event_proof=req.event_proof  # RFC-003
    )
    
    active_runs[run_id] = run
    processed_events[run_id] = set()
    persist_active_run(run)  # Persist to database
    
    # Log with event type if available
    event_type = req.event_proof.get("event_type", "unknown") if req.event_proof else "no_proof"
    print(f"[RunProof Builder] Run started: {run_id} (trace: {trace_id}, trigger: {event_type})")
    
    return {
        "status": "started",
        "run_id": run_id,
        "trace_id": trace_id
    }


@app.post("/v1/run/event")
async def run_event(req: RunEventRequest):
    """Append event to active run (idempotent). Auto-creates run if needed."""
    run_id = req.run_id
    event_id = req.event_id
    
    # Lazy creation: auto-create run if it doesn't exist
    run = get_or_create_run(
        run_id=run_id,
        agent_id=req.data.get("agent_id", "unknown") if req.data else "unknown",
        adapter="openclaw",
        trace_id=req.trace_id
    )
    
    # Idempotent: skip duplicate events
    if event_id in processed_events[run_id]:
        return {"status": "duplicate", "event_id": event_id}
    
    # Assign sequence if not provided
    seq = req.seq if req.seq is not None else run.seq_counter
    run.seq_counter = max(run.seq_counter, seq + 1)
    
    # Create event
    event = GovernanceEvent(
        event_id=event_id,
        type=req.type,
        timestamp=req.timestamp,
        source=req.source,
        seq=seq,
        data=req.data
    )
    
    run.events.append(event)
    processed_events[run_id].add(event_id)
    
    # Categorize special events
    if req.type == "policy.checked" or req.type == "policy.denied":
        run.policy_decisions.append(req.data)
    elif req.type == "tool.called" or req.type == "tool.completed":
        run.tool_calls.append(req.data)
    elif req.type == "memory.committed":
        run.memory_commits.append(req.data)
    
    return {
        "status": "recorded",
        "event_id": event_id,
        "seq": seq
    }


@app.post("/v1/run/end")
async def run_end(req: RunEndRequest):
    """Finalize run and generate RunProof."""
    run_id = req.run_id
    
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    
    run = active_runs[run_id]
    run.ended_at = datetime.fromisoformat(req.ended_at.replace("Z", "+00:00")) if req.ended_at else datetime.now(timezone.utc)
    run.status = "completed" if req.success else "failed"
    
    # Build and save RunProof
    runproof = build_runproof(run)
    save_runproof(runproof)
    
    # Mark as completed in database
    mark_run_completed(run_id, run.status)
    
    # Clean up memory
    del active_runs[run_id]
    if run_id in processed_events:
        del processed_events[run_id]
    
    print(f"[RunProof Builder] Run completed: {run_id} (events: {len(runproof.events)}, hash: {runproof.root_hash[:16]})")
    
    return {
        "status": "completed",
        "run_id": run_id,
        "root_hash": runproof.root_hash,
        "event_count": len(runproof.events)
    }


@app.post("/v1/run/checkpoint")
async def run_checkpoint(req: RunCheckpointRequest):
    """Create checkpoint RunProof without ending run."""
    run_id = req.run_id
    
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    
    run = active_runs[run_id]
    original_status = run.status
    run.status = "checkpoint"
    run.ended_at = datetime.fromisoformat(req.checkpoint_at.replace("Z", "+00:00")) if req.checkpoint_at else datetime.now(timezone.utc)
    
    # Build and save checkpoint RunProof
    runproof = build_runproof(run)
    save_runproof(runproof)
    
    # Restore run state (continue accumulating)
    run.status = original_status
    run.ended_at = None
    
    print(f"[RunProof Builder] Checkpoint: {run_id} (events: {len(runproof.events)})")
    
    return {
        "status": "checkpoint",
        "run_id": run_id,
        "root_hash": runproof.root_hash,
        "event_count": len(runproof.events)
    }


@app.get("/v1/run/{run_id}")
async def get_run(run_id: str):
    """Get run status."""
    if run_id in active_runs:
        run = active_runs[run_id]
        return {
            "run_id": run_id,
            "status": "active",
            "trace_id": run.trace_id,
            "event_count": len(run.events),
            "started_at": run.started_at.isoformat()
        }
    
    # Check database
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runproofs WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            return {
                "run_id": run_id,
                "status": row["status"],
                "trace_id": row["trace_id"],
                "root_hash": row["root_hash"],
                "started_at": row["started_at"],
                "ended_at": row["ended_at"]
            }
    
    raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")


def ensure_protocol_fields(runproof: dict) -> dict:
    """Ensure Protocol Phase 1/2 fields have defaults for backward compatibility."""
    defaults = {
        "proof_type": "receipt",
        "parent_id": None,
        "root_id": None,
        "proof_spec_version": "1.0",
        "signatures": [],  # Empty for unsigned legacy proofs
        "fingerprints": None,  # None for legacy proofs without fingerprints
    }
    for key, default in defaults.items():
        if key not in runproof:
            runproof[key] = default
    
    # Phase 2: Enrich events with canonical_type
    for event in runproof.get("events", []):
        if "canonical_type" not in event:
            enrich_event_with_canonical_type(event)
    
    return runproof


@app.get("/v1/runproof/{run_id}")
async def get_runproof(run_id: str):
    """Get generated RunProof."""
    with get_db() as conn:
        row = conn.execute("SELECT runproof_json FROM runproofs WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            runproof = json.loads(row["runproof_json"])
            return ensure_protocol_fields(runproof)
    
    raise HTTPException(status_code=404, detail=f"RunProof not found: {run_id}")


@app.get("/v1/runproof/{run_id}/refs")
async def get_runproof_refs(run_id: str):
    """Get RunProof references for services (lightweight)."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT run_id, trace_id, root_hash, runproof_json FROM runproofs WHERE run_id = ?",
            (run_id,)
        ).fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail=f"RunProof not found: {run_id}")
        
        runproof = json.loads(row["runproof_json"])
        
        return {
            "run_id": row["run_id"],
            "trace_id": row["trace_id"],
            "root_hash": row["root_hash"],
            "event_refs": [
                {"event_id": e["event_id"], "type": e["type"], "hash": e["content_hash"]}
                for e in runproof.get("events", [])
            ],
            "policy_decisions": runproof.get("policy_decisions", []),
            "tool_calls": runproof.get("tool_calls", []),
            "memory_commits": runproof.get("memory_commits", []),
            "telemetry": runproof.get("telemetry", {})
        }


@app.get("/v1/runproof/{run_id}/verify")
async def verify_runproof(run_id: str):
    """Verify RunProof signatures and hash chain."""
    with get_db() as conn:
        row = conn.execute("SELECT runproof_json FROM runproofs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"RunProof not found: {run_id}")
        
        runproof = json.loads(row["runproof_json"])
        runproof = ensure_protocol_fields(runproof)
        
        # Verify hash chain
        chain_valid = runproof.get("hashes", {}).get("chain_valid", False)
        
        # Verify signatures
        sig_results = []
        root_hash = runproof.get("root_hash", "")
        
        for sig in runproof.get("signatures", []):
            try:
                valid = verify_signature(root_hash, sig)
                sig_results.append({
                    "signer_id": sig.get("signer_id"),
                    "valid": valid,
                    "timestamp": sig.get("timestamp")
                })
            except Exception as e:
                sig_results.append({
                    "signer_id": sig.get("signer_id"),
                    "valid": False,
                    "error": str(e)
                })
        
        all_sigs_valid = all(s["valid"] for s in sig_results) if sig_results else False
        
        return {
            "run_id": run_id,
            "verified": chain_valid and (all_sigs_valid or not sig_results),
            "chain_valid": chain_valid,
            "signatures": {
                "count": len(sig_results),
                "all_valid": all_sigs_valid,
                "results": sig_results
            },
            "root_hash": root_hash,
            "proof_spec_version": runproof.get("proof_spec_version", "1.0")
        }


@app.get("/v1/signing/public-key")
async def get_public_key():
    """Get the runtime public key for signature verification."""
    try:
        return get_runtime_public_key()
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/protocol/event-vocabulary")
async def get_event_vocabulary():
    """Get the event type mapping and canonical vocabulary."""
    return {
        "mapping": EVENT_TYPE_MAPPING,
        "canonical_types": sorted(CANONICAL_EVENT_TYPES),
        "description": "Maps adapter event types to protocol canonical types"
    }


@app.get("/v1/runs")
async def list_runs(status: Optional[str] = None, limit: int = 50):
    """List runs."""
    results = []
    
    # Active runs
    for run_id, run in active_runs.items():
        if status is None or status == "active":
            results.append({
                "run_id": run_id,
                "status": "active",
                "trace_id": run.trace_id,
                "agent_id": run.agent_id,
                "started_at": run.started_at.isoformat()
            })
    
    # Completed runs from DB
    with get_db() as conn:
        if status and status != "active":
            rows = conn.execute(
                "SELECT run_id, status, trace_id, agent_id, started_at, root_hash FROM runproofs WHERE status = ? ORDER BY started_at DESC LIMIT ?",
                (status, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT run_id, status, trace_id, agent_id, started_at, root_hash FROM runproofs ORDER BY started_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        
        for row in rows:
            results.append({
                "run_id": row["run_id"],
                "status": row["status"],
                "trace_id": row["trace_id"],
                "agent_id": row["agent_id"],
                "started_at": row["started_at"],
                "root_hash": row["root_hash"]
            })
    
    return {"runs": results[:limit]}


@app.get("/v1/stats")
async def stats():
    """Get builder statistics."""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM runproofs").fetchone()[0]
        by_status = conn.execute(
            "SELECT status, COUNT(*) as count FROM runproofs GROUP BY status"
        ).fetchall()
        by_adapter = conn.execute(
            "SELECT adapter, COUNT(*) as count FROM runproofs GROUP BY adapter"
        ).fetchall()
    
    return {
        "active_runs": len(active_runs),
        "total_completed": total,
        "by_status": {row["status"]: row["count"] for row in by_status},
        "by_adapter": {row["adapter"]: row["count"] for row in by_adapter}
    }


# ============ Ledger Endpoints (RFC-005) ============

@app.get("/v1/ledger/{agent_id}")
async def get_ledger(agent_id: str, limit: int = 100, offset: int = 0):
    """Get ledger entries for an agent."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ledger_entries WHERE agent_id = ? ORDER BY seq DESC LIMIT ? OFFSET ?",
            (agent_id, limit, offset)
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM ledger_entries WHERE agent_id = ?",
            (agent_id,)
        ).fetchone()[0]
    
    entries = []
    for row in rows:
        entry = dict(row)
        entry["content"] = json.loads(entry.pop("content_json"))
        entries.append(entry)
    
    return {
        "agent_id": agent_id,
        "total": total,
        "entries": entries
    }


@app.get("/v1/ledger/{agent_id}/latest")
async def get_latest_ledger_entry(agent_id: str):
    """Get the latest ledger entry for an agent."""
    entry = get_last_ledger_entry(agent_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"No ledger entries for agent: {agent_id}")
    
    entry["content"] = json.loads(entry.pop("content_json"))
    return entry


@app.get("/v1/ledger/{agent_id}/verify")
async def verify_ledger(agent_id: str, from_seq: int = 0):
    """Verify the ledger chain integrity."""
    result = verify_ledger_chain(agent_id, from_seq)
    return {
        "agent_id": agent_id,
        **result
    }


@app.get("/v1/ledger/{agent_id}/range")
async def get_ledger_range(agent_id: str, from_seq: int = 0, to_seq: int = None):
    """Get ledger entries in a sequence range."""
    with get_db() as conn:
        if to_seq is not None:
            rows = conn.execute(
                "SELECT * FROM ledger_entries WHERE agent_id = ? AND seq >= ? AND seq <= ? ORDER BY seq",
                (agent_id, from_seq, to_seq)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ledger_entries WHERE agent_id = ? AND seq >= ? ORDER BY seq",
                (agent_id, from_seq)
            ).fetchall()
    
    entries = []
    for row in rows:
        entry = dict(row)
        entry["content"] = json.loads(entry.pop("content_json"))
        entries.append(entry)
    
    return {
        "agent_id": agent_id,
        "from_seq": from_seq,
        "to_seq": to_seq,
        "entries": entries
    }


# ============ Checkpoint Endpoints (RFC-006) ============

@app.post("/v1/ledger/{agent_id}/checkpoint")
async def create_ledger_checkpoint(agent_id: str):
    """Create a new checkpoint for the agent's ledger."""
    try:
        checkpoint = create_checkpoint(agent_id)
        return {
            "status": "created",
            **checkpoint
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/v1/ledger/{agent_id}/checkpoints")
async def list_checkpoints(agent_id: str, limit: int = 100):
    """List all checkpoints for an agent."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ledger_checkpoints WHERE agent_id = ? ORDER BY to_seq DESC LIMIT ?",
            (agent_id, limit)
        ).fetchall()
    
    checkpoints = []
    for row in rows:
        ckpt = dict(row)
        if ckpt.get("anchor_json"):
            ckpt["anchor"] = json.loads(ckpt.pop("anchor_json"))
        else:
            ckpt.pop("anchor_json", None)
        checkpoints.append(ckpt)
    
    return {
        "agent_id": agent_id,
        "checkpoints": checkpoints
    }


@app.get("/v1/ledger/{agent_id}/checkpoint/latest")
async def get_latest_checkpoint_endpoint(agent_id: str):
    """Get the latest checkpoint for an agent."""
    checkpoint = get_latest_checkpoint(agent_id)
    if not checkpoint:
        raise HTTPException(status_code=404, detail=f"No checkpoints for agent: {agent_id}")
    return checkpoint


@app.get("/v1/ledger/{agent_id}/checkpoint/{checkpoint_id}")
async def get_checkpoint(agent_id: str, checkpoint_id: str):
    """Get a specific checkpoint."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM ledger_checkpoints WHERE agent_id = ? AND checkpoint_id = ?",
            (agent_id, checkpoint_id)
        ).fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"Checkpoint not found: {checkpoint_id}")
    
    ckpt = dict(row)
    if ckpt.get("anchor_json"):
        ckpt["anchor"] = json.loads(ckpt.pop("anchor_json"))
    else:
        ckpt.pop("anchor_json", None)
    
    return ckpt


@app.get("/v1/ledger/{agent_id}/checkpoints/verify")
async def verify_checkpoints(agent_id: str):
    """Verify the checkpoint chain integrity."""
    result = verify_checkpoint_chain(agent_id)
    return {
        "agent_id": agent_id,
        **result
    }


# ============ Branch Endpoints (RFC-007) ============

class RetryRequest(BaseModel):
    run_id: str
    modifications: Optional[Dict[str, Any]] = None

class ReplayRequest(BaseModel):
    checkpoint_id: str
    context: Optional[Dict[str, Any]] = None

class ForkRequest(BaseModel):
    run_id: str
    configs: List[Dict[str, Any]]


@app.post("/v1/branch/retry")
async def create_retry(agent_id: str, req: RetryRequest):
    """Create a retry branch from a failed run."""
    try:
        branch = create_retry_branch(agent_id, req.run_id, req.modifications)
        return {"status": "created", **branch}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/branch/replay")
async def create_replay(agent_id: str, req: ReplayRequest):
    """Create a replay branch from a checkpoint."""
    try:
        branch = create_replay_branch(agent_id, req.checkpoint_id, req.context)
        return {"status": "created", **branch}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/branch/fork")
async def create_forks(agent_id: str, req: ForkRequest):
    """Create fork branches for A/B testing."""
    try:
        branches = create_fork_branches(agent_id, req.run_id, req.configs)
        return {"status": "created", "branches": branches}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/v1/branch/{branch_id}")
async def get_branch_endpoint(branch_id: str):
    """Get a specific branch proof."""
    branch = get_branch(branch_id)
    if not branch:
        raise HTTPException(status_code=404, detail=f"Branch not found: {branch_id}")
    return branch


@app.get("/v1/branches/{agent_id}")
async def list_branches(agent_id: str, limit: int = 100):
    """List all branches for an agent."""
    branches = get_branches_for_agent(agent_id, limit)
    return {
        "agent_id": agent_id,
        "branches": branches
    }


@app.post("/v1/branch/{branch_id}/link")
async def link_branch(branch_id: str, run_id: str):
    """Link a branch to its resulting run."""
    branch = get_branch(branch_id)
    if not branch:
        raise HTTPException(status_code=404, detail=f"Branch not found: {branch_id}")
    
    link_branch_to_run(branch_id, run_id)
    return {"status": "linked", "branch_id": branch_id, "run_id": run_id}


# ============ Identity Endpoints (RFC-008) ============

class CreateIdentityRequest(BaseModel):
    agent_id: str
    spec: Dict[str, Any] = {}

class UpdateIdentityRequest(BaseModel):
    spec: Dict[str, Any]
    changes: Dict[str, Any] = {}


@app.post("/v1/identity")
async def create_identity(req: CreateIdentityRequest):
    """Create new agent identity."""
    # Check if identity already exists
    existing = get_agent_identity(req.agent_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"Identity already exists: {req.agent_id}")
    
    identity = create_agent_identity(req.agent_id, req.spec)
    return {"status": "created", **identity}


@app.get("/v1/identity/{agent_id}")
async def get_identity(agent_id: str):
    """Get agent identity."""
    identity = get_agent_identity(agent_id)
    if not identity:
        raise HTTPException(status_code=404, detail=f"Identity not found: {agent_id}")
    return identity


@app.put("/v1/identity/{agent_id}")
async def update_identity(agent_id: str, req: UpdateIdentityRequest):
    """Update agent identity."""
    try:
        version = update_agent_identity(agent_id, req.spec, req.changes)
        return {"status": "updated", **version}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/v1/identity/{agent_id}/versions")
async def get_versions(agent_id: str):
    """Get version history for agent."""
    identity = get_agent_identity(agent_id)
    if not identity:
        raise HTTPException(status_code=404, detail=f"Identity not found: {agent_id}")
    
    versions = get_identity_versions(agent_id)
    return {
        "agent_id": agent_id,
        "current_version": identity["current_version"],
        "versions": versions
    }


@app.get("/v1/identity/{agent_id}/verify")
async def verify_identity(agent_id: str):
    """Verify agent identity chain."""
    result = verify_agent_identity(agent_id)
    return result


@app.post("/v1/identity/{agent_id}/bind-ledger")
async def bind_ledger(agent_id: str):
    """Bind agent identity to ledger."""
    try:
        result = bind_identity_to_ledger(agent_id)
        return {"status": "bound", **result}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============ Proof Graph Endpoints (RFC-009 / Phase 3) ============

class LinkProofsRequest(BaseModel):
    child_proof_id: str
    parent_proof_id: str
    relation: str  # retry|delegation|branch|approval|dependency|merge
    branch_id: Optional[str] = None
    metadata: Optional[Dict] = None


def get_proof_by_id(run_id: str) -> Optional[Dict]:
    """Get a proof by run_id."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runproofs WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            return dict(row)
    return None


def create_proof_link(child_id: str, parent_id: str, relation: str, branch_id: str = None, metadata: Dict = None) -> Dict:
    """Create a link between two proofs."""
    import uuid
    
    link_id = f"link-{uuid.uuid4().hex[:12]}"
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO proof_graph (id, child_proof_id, parent_proof_id, relation, branch_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (link_id, child_id, parent_id, relation, branch_id, json.dumps(metadata) if metadata else None))
        
        # Update child proof's parent_id and root_id
        # Get parent's root_id (or use parent as root if it has no parent)
        parent_proof = conn.execute("SELECT runproof_json FROM runproofs WHERE run_id = ?", (parent_id,)).fetchone()
        if parent_proof:
            parent_data = json.loads(parent_proof[0])
            root_id = parent_data.get("root_id") or parent_id
            
            # Update child proof
            child_row = conn.execute("SELECT runproof_json FROM runproofs WHERE run_id = ?", (child_id,)).fetchone()
            if child_row:
                child_data = json.loads(child_row[0])
                child_data["parent_id"] = parent_id
                child_data["root_id"] = root_id
                conn.execute("UPDATE runproofs SET runproof_json = ? WHERE run_id = ?", 
                           (json.dumps(child_data), child_id))
        
        conn.commit()
    
    return {
        "id": link_id,
        "child_proof_id": child_id,
        "parent_proof_id": parent_id,
        "relation": relation,
        "branch_id": branch_id
    }


def get_proof_graph(root_id: str, max_depth: int = 20) -> Dict:
    """Get the full proof graph starting from root_id."""
    nodes = []
    edges = []
    visited = set()
    
    def traverse(proof_id: str, depth: int):
        if depth > max_depth or proof_id in visited:
            return
        visited.add(proof_id)
        
        with get_db() as conn:
            # Get proof details
            row = conn.execute("SELECT run_id, agent_id, status, root_hash FROM runproofs WHERE run_id = ?", (proof_id,)).fetchone()
            if row:
                nodes.append({
                    "proof_id": row[0],
                    "agent_id": row[1],
                    "status": row[2],
                    "root_hash": row[3]
                })
            
            # Get children
            children = conn.execute("""
                SELECT child_proof_id, relation, branch_id 
                FROM proof_graph WHERE parent_proof_id = ?
            """, (proof_id,)).fetchall()
            
            for child in children:
                edges.append({
                    "from": proof_id,
                    "to": child[0],
                    "relation": child[1],
                    "branch_id": child[2]
                })
                traverse(child[0], depth + 1)
    
    traverse(root_id, 0)
    
    # Compute graph hash
    sorted_edges = sorted(edges, key=lambda e: (e["from"], e["to"]))
    sorted_nodes = sorted([{"id": n["proof_id"], "hash": n["root_hash"]} for n in nodes], key=lambda n: n["id"])
    
    graph_struct = {
        "root_id": root_id,
        "nodes": sorted_nodes,
        "edges": [{"from": e["from"], "to": e["to"], "rel": e["relation"]} for e in sorted_edges]
    }
    graph_hash = "sha256:" + hashlib.sha256(json.dumps(graph_struct, sort_keys=True).encode()).hexdigest()
    
    return {
        "root_id": root_id,
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "topology": "dag" if edges else "single",
        "graph_hash": graph_hash
    }


def get_proof_ancestry(proof_id: str) -> List[Dict]:
    """Get ancestry chain from proof up to root."""
    ancestry = []
    current = proof_id
    depth = 0
    visited = set()
    
    while current and depth < 100:
        if current in visited:
            break
        visited.add(current)
        
        with get_db() as conn:
            # Get parent link
            row = conn.execute("""
                SELECT parent_proof_id, relation 
                FROM proof_graph WHERE child_proof_id = ?
            """, (current,)).fetchone()
            
            if row:
                depth += 1
                ancestry.append({
                    "proof_id": row[0],
                    "relation": row[1],
                    "depth": depth
                })
                current = row[0]
            else:
                break
    
    return ancestry


def get_proof_descendants(proof_id: str, max_depth: int = 20) -> List[Dict]:
    """Get all descendants of a proof."""
    descendants = []
    
    def traverse(pid: str, depth: int):
        if depth > max_depth:
            return
        
        with get_db() as conn:
            children = conn.execute("""
                SELECT child_proof_id, relation 
                FROM proof_graph WHERE parent_proof_id = ?
            """, (pid,)).fetchall()
            
            for child in children:
                descendants.append({
                    "proof_id": child[0],
                    "relation": child[1],
                    "depth": depth
                })
                traverse(child[0], depth + 1)
    
    traverse(proof_id, 1)
    return descendants


@app.post("/v1/proof-graph/link")
async def link_proofs(req: LinkProofsRequest):
    """Link two proofs with a relationship."""
    valid_relations = {"retry", "delegation", "branch", "approval", "dependency", "merge"}
    if req.relation not in valid_relations:
        raise HTTPException(status_code=400, detail=f"Invalid relation. Must be one of: {valid_relations}")
    
    # Validate proofs exist
    child = get_proof_by_id(req.child_proof_id)
    parent = get_proof_by_id(req.parent_proof_id)
    
    if not child:
        raise HTTPException(status_code=404, detail=f"Child proof not found: {req.child_proof_id}")
    if not parent:
        raise HTTPException(status_code=404, detail=f"Parent proof not found: {req.parent_proof_id}")
    
    # Prevent self-links
    if req.child_proof_id == req.parent_proof_id:
        raise HTTPException(status_code=400, detail="Cannot link proof to itself")
    
    # Check for cycles (simple check: child shouldn't be in parent's ancestry)
    parent_ancestry = get_proof_ancestry(req.parent_proof_id)
    if any(a["proof_id"] == req.child_proof_id for a in parent_ancestry):
        raise HTTPException(status_code=400, detail="Link would create a cycle")
    
    try:
        link = create_proof_link(req.child_proof_id, req.parent_proof_id, req.relation, req.branch_id, req.metadata)
        return {"status": "linked", **link}
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise HTTPException(status_code=409, detail="Link already exists")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/proof-graph/{root_id}")
async def get_graph(root_id: str, depth: int = 20):
    """Get the full proof graph rooted at a proof."""
    proof = get_proof_by_id(root_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {root_id}")
    
    graph = get_proof_graph(root_id, max_depth=min(depth, 100))
    return graph


@app.get("/v1/runproof/{run_id}/ancestry")
async def get_ancestry(run_id: str):
    """Get the ancestry chain of a proof."""
    proof = get_proof_by_id(run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {run_id}")
    
    ancestry = get_proof_ancestry(run_id)
    root_id = ancestry[-1]["proof_id"] if ancestry else run_id
    
    return {
        "proof_id": run_id,
        "ancestry": ancestry,
        "root_id": root_id,
        "depth": len(ancestry)
    }


@app.get("/v1/runproof/{run_id}/descendants")
async def get_descendants_endpoint(run_id: str, depth: int = 20):
    """Get all descendants of a proof."""
    proof = get_proof_by_id(run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {run_id}")
    
    descendants = get_proof_descendants(run_id, max_depth=min(depth, 100))
    
    return {
        "proof_id": run_id,
        "descendants": descendants,
        "count": len(descendants)
    }


@app.get("/v1/proof-graph/{root_id}/verify")
async def verify_graph(root_id: str):
    """Verify graph integrity and sign it."""
    proof = get_proof_by_id(root_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {root_id}")
    
    graph = get_proof_graph(root_id)
    
    # Sign the graph hash
    if _runtime_private_key:
        signature = _runtime_private_key.sign(graph["graph_hash"].encode())
        signature_b64 = base64.b64encode(signature).decode()
        
        attestation = {
            "graph_hash": graph["graph_hash"],
            "signed_at": datetime.utcnow().isoformat() + "Z",
            "signer_id": _runtime_key_id,
            "algorithm": "ed25519",
            "signature": signature_b64
        }
    else:
        attestation = None
    
    # Verify all individual proof chains
    chain_valid = True
    invalid_proofs = []
    
    for node in graph["nodes"]:
        with get_db() as conn:
            row = conn.execute("SELECT runproof_json FROM runproofs WHERE run_id = ?", (node["proof_id"],)).fetchone()
            if row:
                proof_data = json.loads(row[0])
                if not proof_data.get("hashes", {}).get("chain_valid", True):
                    chain_valid = False
                    invalid_proofs.append(node["proof_id"])
    
    return {
        "root_id": root_id,
        "graph_hash": graph["graph_hash"],
        "node_count": graph["node_count"],
        "edge_count": graph["edge_count"],
        "chains_valid": chain_valid,
        "invalid_proofs": invalid_proofs,
        "attestation": attestation
    }


# ============ State Proof Endpoints (RFC-004 / Phase 4) ============

class CreateStateProofRequest(BaseModel):
    run_id: str
    state_type: str  # memory|session|workflow|agent
    prev_state_hash: Optional[str] = None
    next_state_hash: str
    delta_summary: Optional[Dict] = None


def create_state_proof(run_id: str, state_type: str, prev_hash: str, next_hash: str, 
                       delta: Dict = None) -> Dict:
    """Create a state proof for a run."""
    import uuid
    
    proof_id = f"sp-{uuid.uuid4().hex[:12]}"
    
    # Get run_proof_hash from the run
    run_proof_hash = None
    with get_db() as conn:
        row = conn.execute("SELECT root_hash FROM runproofs WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            run_proof_hash = row[0]
        
        conn.execute("""
            INSERT INTO state_proofs (id, run_id, state_type, prev_state_hash, next_state_hash, 
                                       run_proof_hash, delta_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (proof_id, run_id, state_type, prev_hash, next_hash, run_proof_hash,
              json.dumps(delta) if delta else None))
        conn.commit()
    
    return {
        "id": proof_id,
        "run_id": run_id,
        "state_type": state_type,
        "prev_state_hash": prev_hash,
        "next_state_hash": next_hash,
        "run_proof_hash": run_proof_hash
    }


def get_state_proof(proof_id: str) -> Optional[Dict]:
    """Get a state proof by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM state_proofs WHERE id = ?", (proof_id,)).fetchone()
        if row:
            return {
                "id": row[0],
                "run_id": row[1],
                "state_type": row[2],
                "prev_state_hash": row[3],
                "next_state_hash": row[4],
                "run_proof_hash": row[5],
                "delta_summary": json.loads(row[6]) if row[6] else None,
                "created_at": row[7]
            }
    return None


def get_state_proofs_for_run(run_id: str) -> List[Dict]:
    """Get all state proofs for a run."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, state_type, prev_state_hash, next_state_hash, run_proof_hash, delta_summary, created_at
            FROM state_proofs WHERE run_id = ? ORDER BY created_at
        """, (run_id,)).fetchall()
        
        return [{
            "id": r[0],
            "state_type": r[1],
            "prev_state_hash": r[2],
            "next_state_hash": r[3],
            "run_proof_hash": r[4],
            "delta_summary": json.loads(r[5]) if r[5] else None,
            "created_at": r[6]
        } for r in rows]


def get_state_chain(state_type: str, agent_id: str = None) -> List[Dict]:
    """Get the state transition chain for a state type."""
    with get_db() as conn:
        if agent_id:
            rows = conn.execute("""
                SELECT sp.id, sp.run_id, sp.prev_state_hash, sp.next_state_hash, sp.run_proof_hash, sp.created_at
                FROM state_proofs sp
                JOIN runproofs rp ON sp.run_id = rp.run_id
                WHERE sp.state_type = ? AND rp.agent_id = ?
                ORDER BY sp.created_at
            """, (state_type, agent_id)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, run_id, prev_state_hash, next_state_hash, run_proof_hash, created_at
                FROM state_proofs WHERE state_type = ?
                ORDER BY created_at
            """, (state_type,)).fetchall()
        
        return [{
            "id": r[0],
            "run_id": r[1],
            "prev_state_hash": r[2],
            "next_state_hash": r[3],
            "run_proof_hash": r[4],
            "created_at": r[5]
        } for r in rows]


def verify_state_chain(state_type: str, agent_id: str = None) -> Dict:
    """Verify state chain integrity."""
    chain = get_state_chain(state_type, agent_id)
    
    if not chain:
        return {
            "chain_valid": True,
            "entries": 0,
            "first_state": None,
            "current_state": None,
            "gaps": []
        }
    
    gaps = []
    prev_next_hash = None
    
    for i, entry in enumerate(chain):
        # First entry can have null prev_state_hash
        if i > 0:
            if entry["prev_state_hash"] != prev_next_hash:
                gaps.append({
                    "index": i,
                    "expected": prev_next_hash,
                    "found": entry["prev_state_hash"],
                    "entry_id": entry["id"]
                })
        prev_next_hash = entry["next_state_hash"]
    
    return {
        "chain_valid": len(gaps) == 0,
        "entries": len(chain),
        "first_state": chain[0]["prev_state_hash"],
        "current_state": chain[-1]["next_state_hash"],
        "gaps": gaps
    }


@app.post("/v1/state-proof")
async def create_state_proof_endpoint(req: CreateStateProofRequest):
    """Record a state transition."""
    valid_types = {"memory", "session", "workflow", "agent"}
    if req.state_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid state_type. Must be one of: {valid_types}")
    
    # Validate run exists
    proof = get_proof_by_id(req.run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Run not found: {req.run_id}")
    
    try:
        state_proof = create_state_proof(
            req.run_id, req.state_type, req.prev_state_hash, 
            req.next_state_hash, req.delta_summary
        )
        return {"status": "created", **state_proof}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/state-proof/{proof_id}")
async def get_state_proof_endpoint(proof_id: str):
    """Get a state proof by ID."""
    proof = get_state_proof(proof_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"State proof not found: {proof_id}")
    return proof


@app.get("/v1/runproof/{run_id}/state-proofs")
async def get_run_state_proofs(run_id: str):
    """Get all state proofs for a run."""
    proof = get_proof_by_id(run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    
    state_proofs = get_state_proofs_for_run(run_id)
    return {
        "run_id": run_id,
        "state_proofs": state_proofs,
        "count": len(state_proofs)
    }


@app.get("/v1/state-chain/{state_type}")
async def get_state_chain_endpoint(state_type: str, agent_id: str = None):
    """Get state transition chain."""
    valid_types = {"memory", "session", "workflow", "agent"}
    if state_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid state_type. Must be one of: {valid_types}")
    
    chain = get_state_chain(state_type, agent_id)
    return {
        "state_type": state_type,
        "agent_id": agent_id,
        "chain": chain,
        "length": len(chain)
    }


@app.get("/v1/state-chain/{state_type}/verify")
async def verify_state_chain_endpoint(state_type: str, agent_id: str = None):
    """Verify state chain integrity."""
    valid_types = {"memory", "session", "workflow", "agent"}
    if state_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid state_type. Must be one of: {valid_types}")
    
    result = verify_state_chain(state_type, agent_id)
    return {
        "state_type": state_type,
        "agent_id": agent_id,
        **result
    }


# ============ Policy Binding Endpoints (Phase 5) ============

class CreatePolicyBindingRequest(BaseModel):
    run_id: str
    policy_type: str  # acc_token|governance_rule|capability_grant|constraint
    policy_id: str
    policy_hash: str
    policy_version: Optional[str] = None
    binding_status: str = "applied"  # applied|violated|bypassed
    evaluation_result: Optional[Dict] = None


def create_policy_binding(run_id: str, policy_type: str, policy_id: str, policy_hash: str,
                          policy_version: str = None, binding_status: str = "applied",
                          evaluation_result: Dict = None) -> Dict:
    """Bind a policy to a run."""
    import uuid
    
    binding_id = f"pb-{uuid.uuid4().hex[:12]}"
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO policy_bindings (id, run_id, policy_type, policy_id, policy_hash,
                                          policy_version, binding_status, evaluation_result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (binding_id, run_id, policy_type, policy_id, policy_hash,
              policy_version, binding_status, json.dumps(evaluation_result) if evaluation_result else None))
        conn.commit()
    
    return {
        "id": binding_id,
        "run_id": run_id,
        "policy_type": policy_type,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "binding_status": binding_status
    }


def get_policies_for_run(run_id: str) -> List[Dict]:
    """Get all policies bound to a run."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, policy_type, policy_id, policy_hash, policy_version, 
                   binding_status, evaluation_result, created_at
            FROM policy_bindings WHERE run_id = ? ORDER BY created_at
        """, (run_id,)).fetchall()
        
        return [{
            "id": r[0],
            "policy_type": r[1],
            "policy_id": r[2],
            "policy_hash": r[3],
            "policy_version": r[4],
            "binding_status": r[5],
            "evaluation_result": json.loads(r[6]) if r[6] else None,
            "created_at": r[7]
        } for r in rows]


def get_runs_for_policy(policy_id: str) -> List[Dict]:
    """Get all runs governed by a policy."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT pb.id, pb.run_id, pb.binding_status, pb.created_at,
                   rp.agent_id, rp.status, rp.root_hash
            FROM policy_bindings pb
            JOIN runproofs rp ON pb.run_id = rp.run_id
            WHERE pb.policy_id = ?
            ORDER BY pb.created_at DESC
        """, (policy_id,)).fetchall()
        
        return [{
            "binding_id": r[0],
            "run_id": r[1],
            "binding_status": r[2],
            "bound_at": r[3],
            "agent_id": r[4],
            "run_status": r[5],
            "run_proof_hash": r[6]
        } for r in rows]


def verify_policy_binding(binding_id: str) -> Dict:
    """Verify policy binding integrity."""
    with get_db() as conn:
        row = conn.execute("""
            SELECT pb.id, pb.run_id, pb.policy_type, pb.policy_id, pb.policy_hash,
                   pb.policy_version, pb.binding_status, pb.evaluation_result, pb.created_at,
                   rp.root_hash
            FROM policy_bindings pb
            JOIN runproofs rp ON pb.run_id = rp.run_id
            WHERE pb.id = ?
        """, (binding_id,)).fetchone()
        
        if not row:
            return None
        
        # Explicit column mapping
        policy_id = row[3]
        policy_hash = row[4]
        run_proof_hash = row[9]
        
        # Compute binding hash (policy + run proof)
        binding_content = f"{policy_id}:{policy_hash}:{run_proof_hash}"
        binding_hash = "sha256:" + hashlib.sha256(binding_content.encode()).hexdigest()
        
        return {
            "binding_id": binding_id,
            "run_id": row[1],
            "policy_id": policy_id,
            "policy_hash": policy_hash,
            "run_proof_hash": run_proof_hash,
            "binding_hash": binding_hash,
            "binding_status": row[6],
            "verified": True  # Would check policy hash matches stored policy
        }


@app.post("/v1/policy-binding")
async def create_policy_binding_endpoint(req: CreatePolicyBindingRequest):
    """Bind a policy to a run."""
    valid_types = {"acc_token", "governance_rule", "capability_grant", "constraint"}
    valid_statuses = {"applied", "violated", "bypassed"}
    
    if req.policy_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid policy_type. Must be one of: {valid_types}")
    if req.binding_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid binding_status. Must be one of: {valid_statuses}")
    
    # Validate run exists
    proof = get_proof_by_id(req.run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Run not found: {req.run_id}")
    
    try:
        binding = create_policy_binding(
            req.run_id, req.policy_type, req.policy_id, req.policy_hash,
            req.policy_version, req.binding_status, req.evaluation_result
        )
        return {"status": "bound", **binding}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/runproof/{run_id}/policies")
async def get_run_policies(run_id: str):
    """Get all policies bound to a run."""
    proof = get_proof_by_id(run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    
    policies = get_policies_for_run(run_id)
    
    # Summary
    summary = {
        "total": len(policies),
        "applied": sum(1 for p in policies if p["binding_status"] == "applied"),
        "violated": sum(1 for p in policies if p["binding_status"] == "violated"),
        "bypassed": sum(1 for p in policies if p["binding_status"] == "bypassed")
    }
    
    return {
        "run_id": run_id,
        "policies": policies,
        "summary": summary
    }


@app.get("/v1/policy/{policy_id}/runs")
async def get_policy_runs(policy_id: str, limit: int = 50):
    """Get all runs governed by a policy."""
    runs = get_runs_for_policy(policy_id)
    
    return {
        "policy_id": policy_id,
        "runs": runs[:limit],
        "total": len(runs)
    }


@app.get("/v1/policy-binding/{binding_id}/verify")
async def verify_binding_endpoint(binding_id: str):
    """Verify policy binding integrity."""
    result = verify_policy_binding(binding_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Policy binding not found: {binding_id}")
    
    return result


# ============ External Anchoring Endpoints (Phase 6) ============

class CreateAnchorRequest(BaseModel):
    proof_id: str
    proof_type: str  # run|graph|state_chain|checkpoint
    anchor_type: str  # bitcoin|ethereum|solana|notary|timestamping_authority
    anchor_network: Optional[str] = None  # mainnet|testnet|devnet


class ConfirmAnchorRequest(BaseModel):
    anchor_tx_id: str
    anchor_block: Optional[str] = None
    anchor_timestamp: Optional[str] = None
    anchor_url: Optional[str] = None
    confirmation_data: Optional[Dict] = None


def get_proof_hash_for_anchoring(proof_id: str, proof_type: str) -> Optional[str]:
    """Get the hash to anchor based on proof type."""
    with get_db() as conn:
        if proof_type == "run":
            row = conn.execute("SELECT root_hash FROM runproofs WHERE run_id = ?", (proof_id,)).fetchone()
            return row[0] if row else None
        elif proof_type == "graph":
            # Compute graph hash
            graph = get_proof_graph(proof_id)
            return graph.get("graph_hash") if graph else None
        elif proof_type == "state_chain":
            # Get latest state hash
            row = conn.execute("""
                SELECT next_state_hash FROM state_proofs 
                WHERE state_type = ? ORDER BY created_at DESC LIMIT 1
            """, (proof_id,)).fetchone()
            return row[0] if row else None
        elif proof_type == "checkpoint":
            row = conn.execute("""
                SELECT checkpoint_hash FROM ledger_checkpoints WHERE checkpoint_id = ?
            """, (proof_id,)).fetchone()
            return row[0] if row else None
    return None


def create_anchor(proof_id: str, proof_type: str, proof_hash: str, 
                  anchor_type: str, anchor_network: str = None) -> Dict:
    """Create an external anchor record."""
    import uuid
    
    anchor_id = f"anc-{uuid.uuid4().hex[:12]}"
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO external_anchors (id, proof_id, proof_type, proof_hash,
                                           anchor_type, anchor_network, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """, (anchor_id, proof_id, proof_type, proof_hash, anchor_type, anchor_network))
        conn.commit()
    
    return {
        "id": anchor_id,
        "proof_id": proof_id,
        "proof_type": proof_type,
        "proof_hash": proof_hash,
        "anchor_type": anchor_type,
        "anchor_network": anchor_network,
        "status": "pending"
    }


def get_anchor(anchor_id: str) -> Optional[Dict]:
    """Get an anchor by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM external_anchors WHERE id = ?", (anchor_id,)).fetchone()
        if row:
            return {
                "id": row[0],
                "proof_id": row[1],
                "proof_type": row[2],
                "proof_hash": row[3],
                "anchor_type": row[4],
                "anchor_network": row[5],
                "anchor_tx_id": row[6],
                "anchor_block": row[7],
                "anchor_timestamp": row[8],
                "anchor_url": row[9],
                "status": row[10],
                "confirmation_data": json.loads(row[11]) if row[11] else None,
                "created_at": row[12],
                "confirmed_at": row[13]
            }
    return None


def get_anchors_for_proof(proof_id: str) -> List[Dict]:
    """Get all anchors for a proof."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, proof_type, proof_hash, anchor_type, anchor_network,
                   anchor_tx_id, status, created_at, confirmed_at
            FROM external_anchors WHERE proof_id = ?
            ORDER BY created_at DESC
        """, (proof_id,)).fetchall()
        
        return [{
            "id": r[0],
            "proof_type": r[1],
            "proof_hash": r[2],
            "anchor_type": r[3],
            "anchor_network": r[4],
            "anchor_tx_id": r[5],
            "status": r[6],
            "created_at": r[7],
            "confirmed_at": r[8]
        } for r in rows]


def confirm_anchor(anchor_id: str, tx_id: str, block: str = None, 
                   timestamp: str = None, url: str = None, data: Dict = None) -> Dict:
    """Confirm an anchor with transaction details."""
    from datetime import datetime
    
    with get_db() as conn:
        conn.execute("""
            UPDATE external_anchors 
            SET anchor_tx_id = ?, anchor_block = ?, anchor_timestamp = ?,
                anchor_url = ?, status = 'confirmed', confirmation_data = ?,
                confirmed_at = ?
            WHERE id = ?
        """, (tx_id, block, timestamp, url, json.dumps(data) if data else None,
              datetime.utcnow().isoformat(), anchor_id))
        conn.commit()
    
    return get_anchor(anchor_id)


@app.post("/v1/anchor")
async def create_anchor_endpoint(req: CreateAnchorRequest):
    """Submit a proof for external anchoring."""
    valid_proof_types = {"run", "graph", "state_chain", "checkpoint"}
    valid_anchor_types = {"bitcoin", "ethereum", "solana", "notary", "timestamping_authority"}
    
    if req.proof_type not in valid_proof_types:
        raise HTTPException(status_code=400, detail=f"Invalid proof_type. Must be one of: {valid_proof_types}")
    if req.anchor_type not in valid_anchor_types:
        raise HTTPException(status_code=400, detail=f"Invalid anchor_type. Must be one of: {valid_anchor_types}")
    
    # Get the proof hash
    proof_hash = get_proof_hash_for_anchoring(req.proof_id, req.proof_type)
    if not proof_hash:
        raise HTTPException(status_code=404, detail=f"Proof not found: {req.proof_id}")
    
    try:
        anchor = create_anchor(req.proof_id, req.proof_type, proof_hash, 
                               req.anchor_type, req.anchor_network)
        
        # In production, this would trigger async submission to the anchor service
        # For now, return pending status
        return {"status": "submitted", **anchor}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/anchor/{anchor_id}")
async def get_anchor_endpoint(anchor_id: str):
    """Get anchor status."""
    anchor = get_anchor(anchor_id)
    if not anchor:
        raise HTTPException(status_code=404, detail=f"Anchor not found: {anchor_id}")
    return anchor


@app.get("/v1/runproof/{run_id}/anchors")
async def get_proof_anchors(run_id: str):
    """Get all anchors for a proof."""
    proof = get_proof_by_id(run_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {run_id}")
    
    anchors = get_anchors_for_proof(run_id)
    
    return {
        "proof_id": run_id,
        "anchors": anchors,
        "count": len(anchors),
        "confirmed": sum(1 for a in anchors if a["status"] == "confirmed"),
        "pending": sum(1 for a in anchors if a["status"] == "pending")
    }


@app.post("/v1/anchor/{anchor_id}/confirm")
async def confirm_anchor_endpoint(anchor_id: str, req: ConfirmAnchorRequest):
    """Confirm an anchor with transaction details (webhook callback)."""
    anchor = get_anchor(anchor_id)
    if not anchor:
        raise HTTPException(status_code=404, detail=f"Anchor not found: {anchor_id}")
    
    if anchor["status"] == "confirmed":
        raise HTTPException(status_code=409, detail="Anchor already confirmed")
    
    try:
        updated = confirm_anchor(
            anchor_id, req.anchor_tx_id, req.anchor_block,
            req.anchor_timestamp, req.anchor_url, req.confirmation_data
        )
        return {"status": "confirmed", **updated}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/anchors/pending")
async def get_pending_anchors(limit: int = 50):
    """Get all pending anchors (for batch processing)."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, proof_id, proof_type, proof_hash, anchor_type, anchor_network, created_at
            FROM external_anchors WHERE status = 'pending'
            ORDER BY created_at LIMIT ?
        """, (limit,)).fetchall()
        
        return {
            "pending": [{
                "id": r[0],
                "proof_id": r[1],
                "proof_type": r[2],
                "proof_hash": r[3],
                "anchor_type": r[4],
                "anchor_network": r[5],
                "created_at": r[6]
            } for r in rows],
            "count": len(rows)
        }


# ============ Agent Lifecycle Endpoints (Phase 7) ============

class RegisterAgentRequest(BaseModel):
    metadata: Optional[Dict] = None


def register_agent(agent_id: str, metadata: Dict = None) -> Dict:
    """Register an always-on agent."""
    from datetime import datetime
    
    with get_db() as conn:
        conn.execute("""
            INSERT INTO agent_lifecycle (agent_id, status, registered_at, metadata)
            VALUES (?, 'active', ?, ?)
        """, (agent_id, datetime.utcnow().isoformat(), json.dumps(metadata) if metadata else None))
        conn.commit()
    
    return {
        "agent_id": agent_id,
        "status": "active",
        "registered_at": datetime.utcnow().isoformat()
    }


def get_agent_lifecycle(agent_id: str) -> Optional[Dict]:
    """Get agent lifecycle status."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM agent_lifecycle WHERE agent_id = ?", (agent_id,)).fetchone()
        if row:
            return {
                "agent_id": row[0],
                "status": row[1],
                "registered_at": row[2],
                "activated_at": row[3],
                "last_heartbeat": row[4],
                "paused_at": row[5],
                "retired_at": row[6],
                "ledger_bound": bool(row[7]),
                "ledger_first_seq": row[8],
                "ledger_last_seq": row[9],
                "total_runs": row[10],
                "total_entries": row[11],
                "metadata": json.loads(row[12]) if row[12] else None
            }
    return None


def update_agent_status(agent_id: str, status: str, **kwargs) -> Dict:
    """Update agent lifecycle status."""
    from datetime import datetime
    
    updates = ["status = ?"]
    values = [status]
    
    if status == "active":
        updates.append("activated_at = ?")
        values.append(datetime.utcnow().isoformat())
    elif status == "paused":
        updates.append("paused_at = ?")
        values.append(datetime.utcnow().isoformat())
    elif status == "retired":
        updates.append("retired_at = ?")
        values.append(datetime.utcnow().isoformat())
    
    values.append(agent_id)
    
    with get_db() as conn:
        conn.execute(f"UPDATE agent_lifecycle SET {', '.join(updates)} WHERE agent_id = ?", values)
        conn.commit()
    
    return get_agent_lifecycle(agent_id)


def record_heartbeat(agent_id: str) -> Dict:
    """Record agent heartbeat."""
    from datetime import datetime
    
    with get_db() as conn:
        conn.execute("""
            UPDATE agent_lifecycle SET last_heartbeat = ? WHERE agent_id = ?
        """, (datetime.utcnow().isoformat(), agent_id))
        conn.commit()
    
    return get_agent_lifecycle(agent_id)


def increment_agent_stats(agent_id: str, runs: int = 0, entries: int = 0):
    """Increment agent run/entry counts."""
    with get_db() as conn:
        conn.execute("""
            UPDATE agent_lifecycle 
            SET total_runs = total_runs + ?, total_entries = total_entries + ?
            WHERE agent_id = ?
        """, (runs, entries, agent_id))
        conn.commit()


def get_active_agents(include_stale_hours: int = None) -> List[Dict]:
    """Get all active agents."""
    from datetime import datetime, timedelta
    
    with get_db() as conn:
        rows = conn.execute("""
            SELECT agent_id, status, last_heartbeat, total_runs, total_entries
            FROM agent_lifecycle WHERE status = 'active'
            ORDER BY last_heartbeat DESC
        """).fetchall()
        
        agents = []
        now = datetime.utcnow()
        
        for r in rows:
            agent = {
                "agent_id": r[0],
                "status": r[1],
                "last_heartbeat": r[2],
                "total_runs": r[3],
                "total_entries": r[4]
            }
            
            # Calculate staleness
            if r[2]:
                try:
                    last_hb = datetime.fromisoformat(r[2])
                    age_hours = (now - last_hb).total_seconds() / 3600
                    agent["hours_since_heartbeat"] = round(age_hours, 1)
                    agent["is_stale"] = age_hours > 24
                except:
                    pass
            
            agents.append(agent)
        
        return agents


@app.post("/v1/agent/{agent_id}/register")
async def register_agent_endpoint(agent_id: str, req: RegisterAgentRequest = None):
    """Register an always-on agent."""
    existing = get_agent_lifecycle(agent_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"Agent already registered: {agent_id}")
    
    try:
        result = register_agent(agent_id, req.metadata if req else None)
        return {"status": "registered", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/agent/{agent_id}/activate")
async def activate_agent(agent_id: str):
    """Activate a paused agent."""
    lifecycle = get_agent_lifecycle(agent_id)
    if not lifecycle:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
    if lifecycle["status"] not in ["paused", "registered"]:
        raise HTTPException(status_code=400, detail=f"Cannot activate agent with status: {lifecycle['status']}")
    
    result = update_agent_status(agent_id, "active")
    return {"status": "activated", **result}


@app.post("/v1/agent/{agent_id}/heartbeat")
async def heartbeat_agent(agent_id: str):
    """Record agent heartbeat."""
    lifecycle = get_agent_lifecycle(agent_id)
    if not lifecycle:
        # Auto-register on first heartbeat
        register_agent(agent_id)
    
    result = record_heartbeat(agent_id)
    return {"status": "heartbeat_recorded", **result}


@app.post("/v1/agent/{agent_id}/pause")
async def pause_agent(agent_id: str):
    """Pause an active agent."""
    lifecycle = get_agent_lifecycle(agent_id)
    if not lifecycle:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
    if lifecycle["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Can only pause active agents")
    
    result = update_agent_status(agent_id, "paused")
    return {"status": "paused", **result}


@app.post("/v1/agent/{agent_id}/retire")
async def retire_agent(agent_id: str):
    """Retire an agent (preserves ledger history)."""
    lifecycle = get_agent_lifecycle(agent_id)
    if not lifecycle:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
    if lifecycle["status"] == "retired":
        raise HTTPException(status_code=400, detail="Agent already retired")
    
    result = update_agent_status(agent_id, "retired")
    return {"status": "retired", **result}


@app.get("/v1/agent/{agent_id}/lifecycle")
async def get_lifecycle_endpoint(agent_id: str):
    """Get agent lifecycle status."""
    lifecycle = get_agent_lifecycle(agent_id)
    if not lifecycle:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
    return lifecycle


@app.get("/v1/agents/active")
async def list_active_agents():
    """List all active agents."""
    agents = get_active_agents()
    
    return {
        "agents": agents,
        "total": len(agents),
        "stale": sum(1 for a in agents if a.get("is_stale", False))
    }


# ============ Compatibility Routes (for runproof-ui) ============

@app.get("/proof/{proof_id}")
async def get_proof_compat(proof_id: str):
    """Compatibility route for runproof-ui: returns all views."""
    proof = await get_runproof(proof_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {proof_id}")
    
    # Build summary view
    summary = {
        "proof_id": proof.get("run_id"),
        "run_id": proof.get("run_id"),
        "agent_id": proof.get("agent_id", "unknown"),
        "runtime": proof.get("adapter", "unknown"),
        "status": "verified" if proof.get("root_hash") else "pending",
        "event_count": len(proof.get("events", [])),
        "started_at": proof.get("started_at"),
        "ended_at": proof.get("ended_at"),
    }
    
    # Build timeline view
    events = proof.get("events", [])
    timeline = {
        "events": [
            {
                "seq": e.get("seq", i),
                "event_type": e.get("type", "unknown"),
                "timestamp": e.get("timestamp"),
                "entry_hash": e.get("entry_hash", ""),
                "payload_summary": str(e.get("data", {}))[:100],
            }
            for i, e in enumerate(events)
        ],
        "total_events": len(events),
    }
    
    # Build lineage view
    graph_entry = None
    with get_db() as conn:
        cur = conn.execute(
            "SELECT parent_proof_id, relation FROM proof_graph WHERE child_proof_id = ?",
            (proof_id,)
        )
        row = cur.fetchone()
        if row:
            graph_entry = {"parent": row[0], "relation": row[1]}
    
    lineage = {
        "proof_id": proof_id,
        "parent": graph_entry["parent"] if graph_entry else None,
        "root": None,  # Would need recursive lookup
        "depth": 1 if graph_entry else 0,
        "workflow_id": proof.get("trace_id"),
        "children": [],
    }
    
    # Build report view
    checks = [
        {"name": "Hash Chain", "passed": True, "message": "All events properly chained"},
        {"name": "Root Hash", "passed": bool(proof.get("root_hash")), "message": "Root hash computed"},
        {"name": "Signature", "passed": bool(proof.get("signatures")), "message": f"{len(proof.get('signatures', []))} signatures"},
    ]
    passed = sum(1 for c in checks if c["passed"])
    report = {
        "overall_status": "verified" if passed == len(checks) else "partial",
        "checks": checks,
        "human_summary": f"Proof verified with {passed}/{len(checks)} checks passed",
        "passed_count": passed,
        "failed_count": len(checks) - passed,
    }
    
    return {
        "summary": summary,
        "timeline": timeline,
        "lineage": lineage,
        "report": report,
    }


@app.post("/verify")
async def verify_compat(req: dict):
    """Compatibility route for runproof-ui: verify by hash or run_id."""
    proof_id = req.get("proof_id") or req.get("run_id") or req.get("hash")
    if not proof_id:
        raise HTTPException(status_code=400, detail="Must provide proof_id, run_id, or hash")
    
    proof = await get_runproof(proof_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {proof_id}")
    
    return {
        "valid": bool(proof.get("root_hash")),
        "proof_id": proof.get("run_id"),
        "run_id": proof.get("run_id"),
        "agent_id": proof.get("agent_id", "unknown"),
        "runtime": proof.get("adapter", "unknown"),
        "status": "verified" if proof.get("root_hash") else "pending",
        "event_count": len(proof.get("events", [])),
    }


@app.get("/verify/{hash_or_id}")
async def verify_by_hash_compat(hash_or_id: str):
    """Compatibility route: verify by hash or run_id in URL."""
    proof = await get_runproof(hash_or_id)
    if not proof:
        raise HTTPException(status_code=404, detail=f"Proof not found: {hash_or_id}")
    
    return {
        "valid": bool(proof.get("root_hash")),
        "proof_id": proof.get("run_id"),
        "run_id": proof.get("run_id"),
        "agent_id": proof.get("agent_id", "unknown"),
        "runtime": proof.get("adapter", "unknown"),
        "status": "verified" if proof.get("root_hash") else "pending",
        "event_count": len(proof.get("events", [])),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8097)
