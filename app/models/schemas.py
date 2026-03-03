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
from pydantic import EmailStr

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
    """Base incident model with camelCase fields matching frontend."""
    source_ip: str = Field(..., alias="sourceIp")
    app_name: str = Field(..., alias="targetApp")
    risk_level: RiskLevel
    anomaly_count: int = 0
    first_seen: datetime
    last_seen: datetime
    status: IncidentStatus = IncidentStatus.OPEN

    class Config:
        populate_by_name = True  # Allow both snake_case and camelCase
        from_attributes = True


class IncidentCreate(BaseModel):
    """Incident creation model with camelCase fields."""
    id: str
    event_name: str = Field(..., alias="eventName")
    timestamp: str
    severity: str  # 'Critical' | 'High' | 'Medium' | 'Low' | 'Healthy'
    source_ip: str = Field(..., alias="sourceIp")
    dest_ip: str = Field(..., alias="destIp")
    target_app: str = Field(..., alias="targetApp")
    status: str = Field(default="Active")  # 'Active' | 'Contained' | 'Closed'
    event_details: str = Field(default="", alias="eventDetails")
    raw_logs: List[Dict[str, Any]] = Field(default_factory=list)
    anomaly_results: List[AnomalyResult] = Field(default_factory=list)

    class Config:
        populate_by_name = True
        from_attributes = True


class IncidentResponse(BaseModel):
    """Incident response model with camelCase fields matching frontend."""
    id: str
    event_name: str = Field(..., alias="eventName")
    timestamp: str
    severity: str
    source_ip: str = Field(..., alias="sourceIp")
    dest_ip: str = Field(..., alias="destIp")
    target_app: str = Field(..., alias="targetApp")
    status: str  # 'Active' | 'Contained' | 'Closed'
    event_details: str = Field(default="", alias="eventDetails")
    risk_level: Optional[RiskLevel] = None
    anomaly_count: int = 0
    containment_status: ContainmentStatus = ContainmentStatus.NONE
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        from_attributes = True


class IncidentListResponse(BaseModel):
    total: int
    incidents: List[IncidentResponse]

    class Config:
        from_attributes = True


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
    llm_model_used: str


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


# ─────────────────────────────────────────────
# Network Metrics  (routes_network.py)
# ─────────────────────────────────────────────

class NetworkNode(BaseModel):
    """A source IP node in the network traffic graph."""
    id:            str
    ip:            str
    request_count: int
    bytes_sent:    int
    status:        str   = "normal"   # "normal" | "warning" | "blocked"
    top_paths:     List[str] = Field(default_factory=list)


class NetworkAnomaly(BaseModel):
    """A flagged anomaly detected from Apache/network logs."""
    id:           str
    source_ip:    str
    anomaly_type: str     # "high_error_rate" | "excessive_requests" | "server_error"
    request_count: int
    error_count:  int
    severity:     str     # "Low" | "Medium" | "High" | "Critical"
    first_seen:   str
    last_seen:    str
    sample_paths: List[str] = Field(default_factory=list)


class NetworkMetricsResponse(BaseModel):
    """Full response for GET /api/metrics/network"""
    nodes:           List[NetworkNode]
    anomalies:       List[NetworkAnomaly]
    bandwidth_usage: Dict[str, Any]       # total bytes, hourly chart data, etc.
    summary:         Dict[str, Any]       # total_requests, unique_ips, error_rate


# ─────────────────────────────────────────────
# Endpoint Security  (routes_endpoints.py)
# ─────────────────────────────────────────────

class EndpointAlert(BaseModel):
    """A single security alert parsed from syslog / Windows event logs."""
    id:              str
    workstation_id:  str
    alert_type:      str     # "ssh_brute_force" | "failed_login" | "system_error" etc.
    source_ip:       Optional[str] = None
    username:        Optional[str] = None
    message:         str
    severity:        str     # "Low" | "Medium" | "High" | "Critical"
    timestamp:       str
    raw_line:        Optional[str] = None


class EndpointMetricsResponse(BaseModel):
    """Full response for GET /api/metrics/endpoints"""
    alerts:           List[EndpointAlert]
    summary:          Dict[str, Any]   # total_alerts, critical_count, affected_hosts
    auth_failure_ips: List[Dict[str, Any]]   # top IPs causing auth failures


# ─────────────────────────────────────────────
# Recent Incidents for LLM feed  (routes_incidents.py)
# ─────────────────────────────────────────────

class RecentIncident(BaseModel):
    """Combined critical event ready for LLM threat briefing."""
    id:           str
    source:       str   # "apache" | "syslog" | "windows_event"
    event_type:   str
    source_ip:    Optional[str] = None
    username:     Optional[str] = None
    severity:     str
    timestamp:    str
    description:  str
    raw_evidence: List[str] = Field(default_factory=list)


class RecentIncidentsResponse(BaseModel):
    """Full response for GET /api/incidents/recent"""
    incidents:   List[RecentIncident]
    total:       int
    generated_at: str


# ─────────────────────────────────────────────
# Dashboard Data Schemas (Matching Frontend)
# ─────────────────────────────────────────────

class TimeSeriesData(BaseModel):
    """Time series chart data point."""
    name: str
    value: Optional[float] = None
    requests: Optional[int] = None
    errors: Optional[int] = None
    latency: Optional[float] = None

    class Config:
        extra = "allow"  # Allow additional fields for flexible chart data


class AppHealth(BaseModel):
    """Application health status for overview page."""
    id: str
    name: str
    load: str
    status: str  # 'Healthy' | 'Warning' | 'Critical'
    status_text: Optional[str] = Field(default=None, alias="statusText")
    action: str  # 'View Traffic' | 'Apply Hard Limit' | 'Isolate DB'

    class Config:
        populate_by_name = True
        from_attributes = True


class ThreatAnomaly(BaseModel):
    """Threat anomaly for overview page."""
    id: str
    severity: str  # 'Critical' | 'High' | 'Medium' | 'Low' | 'Healthy'
    target_app: str = Field(..., alias="targetApp")
    source: str
    issue: str
    actions: List[str] = Field(default_factory=list)

    class Config:
        populate_by_name = True
        from_attributes = True


class MicroservicePosition(BaseModel):
    """Position for microservice node."""
    top: str
    left: str


class Microservice(BaseModel):
    """Microservice node for topology view."""
    id: str
    name: str
    status: str  # 'Healthy' | 'Failing'
    position: MicroservicePosition
    connections: List[str] = Field(default_factory=list)


class OverviewData(BaseModel):
    """Overview page dashboard data."""
    app_health: List[AppHealth] = Field(..., alias="appHealth")
    threat_anomalies: List[ThreatAnomaly] = Field(..., alias="threatAnomalies")
    microservices: List[Microservice]

    class Config:
        populate_by_name = True


# ─────────────────────────────────────────────
# API Monitoring Page
# ─────────────────────────────────────────────

class ApiRoute(BaseModel):
    """API route for monitoring."""
    id: int
    app: str
    path: str
    method: str
    cost: float
    trend: float
    action: str


class ApiMonitoringData(BaseModel):
    """API monitoring dashboard data."""
    api_calls_today: int = Field(..., alias="apiCallsToday")
    blocked_requests: int = Field(..., alias="blockedRequests")
    avg_latency: float = Field(..., alias="avgLatency")
    estimated_cost: float = Field(..., alias="estimatedCost")
    api_usage_chart: List[TimeSeriesData] = Field(..., alias="apiUsageChart")
    api_routing: List[ApiRoute] = Field(..., alias="apiRouting")

    class Config:
        populate_by_name = True


# ─────────────────────────────────────────────
# Network Traffic Page
# ─────────────────────────────────────────────

class NetworkAnomalyFrontend(BaseModel):
    """Network anomaly with camelCase for frontend (different from backend NetworkAnomaly)."""
    id: int
    source_endpoint: str = Field(..., alias="sourceEndpoint")
    target_app: str = Field(..., alias="targetApp")
    port: int
    type: str

    class Config:
        populate_by_name = True
        from_attributes = True


class NetworkTrafficData(BaseModel):
    """Network traffic dashboard data."""
    bandwidth: float
    active_connections: int = Field(..., alias="activeConnections")
    dropped_packets: int = Field(..., alias="droppedPackets")
    network_anomalies: List[NetworkAnomalyFrontend] = Field(..., alias="networkAnomalies")

    class Config:
        populate_by_name = True


# ─────────────────────────────────────────────
# Endpoint Security Page
# ─────────────────────────────────────────────

class OsDistribution(BaseModel):
    """OS distribution chart data."""
    name: str
    value: int
    fill: str


class AlertTypeDistribution(BaseModel):
    """Alert type distribution chart data."""
    name: str
    value: int
    fill: str


class WazuhEvent(BaseModel):
    """Wazuh security event."""
    id: int
    workstation_id: str = Field(..., alias="workstationId")
    employee: str
    avatar: str
    alert: str
    severity: str  # 'Critical' | 'High' | 'Medium' | 'Low' | 'Healthy'

    class Config:
        populate_by_name = True
        from_attributes = True


class EndpointSecurityData(BaseModel):
    """Endpoint security dashboard data."""
    monitored_laptops: int = Field(..., alias="monitoredLaptops")
    offline_devices: int = Field(..., alias="offlineDevices")
    malware_alerts: int = Field(..., alias="malwareAlerts")
    os_distribution: List[OsDistribution] = Field(..., alias="osDistribution")
    alert_types: List[AlertTypeDistribution] = Field(..., alias="alertTypes")
    wazuh_events: List[WazuhEvent] = Field(..., alias="wazuhEvents")

    class Config:
        populate_by_name = True


# ─────────────────────────────────────────────
# DB Monitoring Page
# ─────────────────────────────────────────────

class SuspiciousActivity(BaseModel):
    """Suspicious database activity."""
    id: int
    app: str
    user: str
    type: str
    table: str
    reason: str


class DbMonitoringData(BaseModel):
    """Database monitoring dashboard data."""
    active_connections: int = Field(..., alias="activeConnections")
    avg_query_latency: float = Field(..., alias="avgQueryLatency")
    data_export_volume: float = Field(..., alias="dataExportVolume")
    operations_chart: List[TimeSeriesData] = Field(..., alias="operationsChart")
    suspicious_activity: List[SuspiciousActivity] = Field(..., alias="suspiciousActivity")

    class Config:
        populate_by_name = True


# ─────────────────────────────────────────────
# Quarantined Endpoints
# ─────────────────────────────────────────────

class QuarantinedEndpoint(BaseModel):
    """Quarantined endpoint for security response."""
    id: str
    hostname: str
    quarantined_at: str = Field(..., alias="quarantinedAt")
    reason: str

    class Config:
        populate_by_name = True
        from_attributes = True


# ─────────────────────────────────────────────
# Reports Page
# ─────────────────────────────────────────────

class ScheduledReport(BaseModel):
    """Scheduled report configuration."""
    id: str
    title: str
    schedule: str
    is_active: bool = Field(..., alias="isActive")

    class Config:
        populate_by_name = True
        from_attributes = True


class RecentDownload(BaseModel):
    """Recently generated report download."""
    id: str
    name: str
    generated: str
    url: str

    class Config:
        from_attributes = True

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str  # Required - matches frontend SignupData
    role: Optional[str] = "analyst"  # Optional, defaults to "analyst"


class SignupResponse(BaseModel):
    user_id: int  # Changed from str to int to match DB
    email: EmailStr
    full_name: str
    role: str
    message: str = "Account created successfully. You may now log in."
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int = 7200  # 2 hours in seconds - matches JWT expiry
    role: str  # Added for frontend
    full_name: str  # Added for frontend

    class Config:
        from_attributes = True


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    message: str = "If the account exists, a reset link has been sent."


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ResetPasswordResponse(BaseModel):
    message: str = "Password reset successfully"
    password_updated: bool = True
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UserProfile(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    first_name: str = ""  # Added for frontend compatibility
    last_name: str = ""  # Added for frontend compatibility
    phone_number: str = ""  # Added for frontend
    timezone: str = "UTC"  # Added for frontend
    enable_2fa: bool = False  # Added for frontend
    role: str  # Added for frontend
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None  # Added

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Team / User Management (Settings Page)
# ─────────────────────────────────────────────

class TeamUser(BaseModel):
    """User representation for team management in settings page."""
    id: int
    name: str  # Frontend uses 'name' not 'full_name'
    email: EmailStr
    role: str  # "Global Admin" | "Tier 1 Analyst" etc.
    scope: List[str] = Field(default_factory=list)
    avatar: str = ""
    status: str = "Active"  # "Active" | "Invite Pending"

    class Config:
        from_attributes = True


class AccountActivity(BaseModel):
    """User account activity log entry."""
    id: str
    date_time: str  # Frontend uses dateTime (camelCase in JSON)
    ip: str
    location: str
    status: str

    class Config:
        from_attributes = True