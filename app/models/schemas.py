"""
models/schemas.py

Pydantic models serve as the contract between the ATLAS backend and frontend.
Strict typing here prevents malformed data from entering the ML pipeline
or being returned to the SOC dashboard.
"""

from pydantic import BaseModel, Field, IPvAnyAddress
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContainmentStatus(str, Enum):
    NONE = "none"
    WARNING = "warning"
    SOFT_LIMITED = "soft_limited"
    HARD_BLOCKED = "hard_blocked"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


# ─────────────────────────────────────────────
# Log Event
# ─────────────────────────────────────────────

class LogEvent(BaseModel):
    """Represents a single normalized log entry from any source."""
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    app_name: str
    log_type: str  # api | db | network | endpoint
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    bytes_sent: Optional[int] = None
    endpoint: Optional[str] = None
    user_agent: Optional[str] = None
    raw_message: str


# ─────────────────────────────────────────────
# Anomaly Detection
# ─────────────────────────────────────────────

class AnomalyResult(BaseModel):
    """Output from the IsolationForest anomaly detection pipeline."""
    is_anomaly: bool
    anomaly_score: float = Field(..., description="Negative scores indicate anomalies (IsolationForest convention)")
    deviation_features: Dict[str, float] = Field(
        default_factory=dict,
        description="Which features deviated and by how much from baseline"
    )
    confidence: float = Field(..., ge=0.0, le=1.0)
    detected_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────
# Incidents
# ─────────────────────────────────────────────

class IncidentBase(BaseModel):
    source_ip: str
    app_name: str
    risk_level: RiskLevel
    anomaly_count: int = 0
    first_seen: datetime
    last_seen: datetime
    status: IncidentStatus = IncidentStatus.OPEN


class IncidentCreate(IncidentBase):
    raw_logs: List[Dict[str, Any]] = Field(default_factory=list)
    anomaly_results: List[AnomalyResult] = Field(default_factory=list)


class IncidentResponse(IncidentBase):
    incident_id: str
    containment_status: ContainmentStatus = ContainmentStatus.NONE
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


class IncidentListResponse(BaseModel):
    total: int
    incidents: List[IncidentResponse]


# ─────────────────────────────────────────────
# AI Copilot / SOC Briefing
# ─────────────────────────────────────────────

class SOCBriefingRequest(BaseModel):
    """Payload the frontend sends when triggering an AI investigation."""
    incident_id: str
    include_raw_logs: bool = False


class SOCBriefing(BaseModel):
    """
    Structured output from the LLM Copilot.
    Having a fixed schema prevents unstructured LLM text from breaking
    the frontend dashboard rendering pipeline.
    """
    incident_id: str
    threat_summary: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    recommended_action: str
    ioc_indicators: List[str] = Field(
        default_factory=list,
        description="Indicators of Compromise identified by the LLM"
    )
    mitre_tactics: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics the LLM matched"
    )
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    model_used: str


# ─────────────────────────────────────────────
# Dashboard Metrics
# ─────────────────────────────────────────────

class APIUsageStat(BaseModel):
    app_name: str
    timestamp: str
    request_count: int
    error_rate: float
    avg_latency_ms: float
    cost_usd: Optional[float] = None  # For third-party APIs with billing


class DBLatencyStat(BaseModel):
    db_name: str
    timestamp: str
    avg_latency_ms: float
    slow_query_count: int
    p99_latency_ms: float


class DashboardSummary(BaseModel):
    total_open_incidents: int
    critical_count: int
    high_count: int
    blocked_ips: int
    anomalies_last_hour: int
    top_offending_ips: List[Dict[str, Any]]


# ─────────────────────────────────────────────
# Risk Containment
# ─────────────────────────────────────────────

class ContainmentAction(BaseModel):
    """Result of the progressive containment evaluation."""
    ip_address: str
    app_name: str
    anomaly_count: int
    action_taken: ContainmentStatus
    message: str
    escalated_to_wazuh: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────
# Settings / Rules
# ─────────────────────────────────────────────

class ContainmentRule(BaseModel):
    rule_id: str
    name: str
    warn_threshold: int = 1
    soft_limit_threshold: int = 3
    hard_block_threshold: int = 5
    applies_to_apps: List[str] = Field(default_factory=list)
    enabled: bool = True


class ContainmentRuleUpdate(BaseModel):
    warn_threshold: Optional[int] = None
    soft_limit_threshold: Optional[int] = None
    hard_block_threshold: Optional[int] = None
    enabled: Optional[bool] = None
