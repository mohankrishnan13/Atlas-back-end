"""
api/routes_incidents.py

Incident management endpoints and the AI Copilot investigation trigger.

New endpoint added for prototype phase:
    GET /api/incidents/recent
    — Combines the most severe anomalies from Apache logs and Syslog/Windows
      Event Logs into a single prioritised incident feed. This is the data
      that will be fed into Ollama for AI threat briefing.

Original endpoints preserved:
    GET    /api/v1/incidents               — paginated incident list (ES-backed)
    GET    /api/v1/incidents/{id}          — single incident detail
    POST   /api/v1/incidents/{id}/investigate — AI Copilot analysis
    PUT    /api/v1/incidents/{id}/status   — analyst status update
    POST   /api/v1/incidents/{id}/containment/reset
    GET    /api/v1/incidents/ip/{ip}/status
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from fastapi.responses import JSONResponse

from app.integrations.elastic_client import ElasticClient
from app.integrations.llm_copilot import AICopilotAnalyst
from app.models.schemas import (
    ContainmentStatus,
    IncidentListResponse,
    IncidentResponse,
    IncidentStatus,
    RecentIncident,
    RecentIncidentsResponse,
    SOCBriefing,
    SOCBriefingRequest,
)
from app.services.incident_service import IncidentService
from app.services.risk_manager import ProgressiveContainmentManager
from app.utils.log_parser import (
    aggregate_endpoint_alerts,
    aggregate_network_metrics,
    build_recent_incidents,
    fetch_recent_network_logs,
    fetch_recent_syslog_events,
    fetch_recent_windows_events,
)

logger = logging.getLogger(__name__)

# ── Two routers with different prefixes ───────────────────────────────────────
# router_v1   — original /api/v1/incidents  (ES-backed production routes)
# router_proto — new /api/incidents         (prototype log-file routes)
router_v1    = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])
router_proto = APIRouter(prefix="/api/incidents",    tags=["Incidents (Prototype)"])

# For backward compatibility we also export `router` pointing at router_v1
router = router_v1

# ─── Module-level singletons ─────────────────────────────────────────────────

_elastic:          Optional[ElasticClient]               = None
_copilot:          Optional[AICopilotAnalyst]             = None
_risk_manager:     Optional[ProgressiveContainmentManager] = None
_incident_service: Optional[IncidentService]              = None


def init_dependencies(
    elastic:      ElasticClient,
    copilot:      AICopilotAnalyst,
    risk_manager: ProgressiveContainmentManager,
) -> None:
    global _elastic, _copilot, _risk_manager, _incident_service
    _elastic          = elastic
    _copilot          = copilot
    _risk_manager     = risk_manager
    _incident_service = IncidentService(elastic)


def get_elastic() -> ElasticClient:
    if not _elastic:
        raise HTTPException(503, "ElasticClient not initialized.")
    return _elastic


def get_copilot() -> AICopilotAnalyst:
    if not _copilot:
        raise HTTPException(503, "AI Copilot not initialized.")
    return _copilot


def get_incident_service() -> IncidentService:
    if not _incident_service:
        raise HTTPException(503, "IncidentService not initialized.")
    return _incident_service


def get_risk_manager() -> ProgressiveContainmentManager:
    if not _risk_manager:
        raise HTTPException(503, "RiskManager not initialized.")
    return _risk_manager


# ─── Prototype route: /api/incidents/recent ───────────────────────────────────

@router_proto.get("/recent", response_model=RecentIncidentsResponse)
async def get_recent_incidents(
    hours: int = Query(
        default=24,
        ge=1,
        le=168,
        description="Look-back window in hours",
    ),
    limit: int = Query(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of incidents to return",
    ),
) -> RecentIncidentsResponse:
    """
    Merges the most severe anomalies from Apache access logs (network layer)
    and Linux Syslog / Windows Event Logs (endpoint layer) into a single
    prioritised incident feed.

    This endpoint is designed as the data source for the Ollama AI Threat
    Briefing feature: the top-N events are returned in a structured format
    that can be serialised directly into an LLM prompt for threat analysis.

    Severity priority order: Critical > High > Medium  (Low events excluded)
    Sources combined:
        - Apache logs  → excessive requests, high error rate, server errors
        - Linux Syslog → SSH brute force, auth failures, sudo failures, kernel panics
        - Windows EVT  → logon failures (event IDs 529 / 4625), system errors

    TODO [PRODUCTION]: Replace all fetch_recent_*() calls with ES queries:
    e.g., elastic_client.search(index="atlas-logs-*", ...)
    """
    # ── Fetch from local log files ────────────────────────────────────────────
    # TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    # e.g., response = elastic_client.search(index="atlas-network-logs", ...)
    network_records = []
    try:
        network_records = fetch_recent_network_logs(hours=hours)
    except Exception as exc:
        logger.error(f"[recent_incidents] Apache log read failed: {exc}")

    # TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    # e.g., response = elastic_client.search(index="atlas-syslog-*", ...)
    syslog_records = []
    try:
        syslog_records = fetch_recent_syslog_events(hours=hours)
    except Exception as exc:
        logger.error(f"[recent_incidents] Syslog read failed: {exc}")

    # TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    # e.g., response = elastic_client.search(index="atlas-winevent-*", ...)
    windows_records = []
    try:
        windows_records = fetch_recent_windows_events(hours=hours)
    except Exception as exc:
        logger.error(f"[recent_incidents] Windows event log read failed: {exc}")

    # ── Aggregate each source ─────────────────────────────────────────────────
    net_aggregated = aggregate_network_metrics(network_records, top_n=20)
    ep_aggregated  = aggregate_endpoint_alerts(syslog_records, windows_records, top_n=100)

    # ── Merge into unified incident list ──────────────────────────────────────
    raw_incidents = build_recent_incidents(
        network_anomalies=net_aggregated["anomalies"],
        endpoint_alerts=ep_aggregated["alerts"],
        top_n=limit,
    )

    incidents = [
        RecentIncident(
            id=inc["id"],
            source=inc["source"],
            event_type=inc["event_type"],
            source_ip=inc.get("source_ip"),
            username=inc.get("username"),
            severity=inc["severity"],
            timestamp=inc["timestamp"],
            description=inc["description"],
            raw_evidence=inc.get("raw_evidence", []),
        )
        for inc in raw_incidents
    ]

    logger.info(
        f"[recent_incidents] Returning {len(incidents)} incidents "
        f"(network: {len(net_aggregated['anomalies'])}, "
        f"endpoint: {len(ep_aggregated['alerts'])} alerts combined)."
    )

    return RecentIncidentsResponse(
        incidents=incidents,
        total=len(incidents),
        generated_at=datetime.utcnow().isoformat(),
    )


# ─── Original /api/v1/incidents routes (ES-backed) ───────────────────────────

@router_v1.get("", response_model=IncidentListResponse)
async def list_incidents(
    status:     Optional[str] = Query(None, description="Filter by incident status"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    page:       int           = Query(1,  ge=1),
    size:       int           = Query(20, ge=1, le=100),
    elastic:    ElasticClient = Depends(get_elastic),
) -> IncidentListResponse:
    """Paginated list of all incidents. Frontend SOC table view."""
    result = await elastic.list_incidents(
        status=status, risk_level=risk_level, page=page, size=size
    )
    return IncidentListResponse(
        total=result["total"],
        incidents=[IncidentResponse(**i) for i in result["incidents"]],
    )


@router_v1.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id:      str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> IncidentResponse:
    """Retrieve a single incident by ID."""
    data = await incident_service.get_incident_with_context(incident_id)
    if not data:
        raise HTTPException(404, f"Incident {incident_id} not found.")
    data.pop("recent_logs", None)
    data.pop("log_count",   None)
    return IncidentResponse(**data)


@router_v1.post("/{incident_id}/investigate", response_model=SOCBriefing)
async def investigate_incident(
    incident_id:      str,
    request:          SOCBriefingRequest = Body(default=SOCBriefingRequest(incident_id="")),
    incident_service: IncidentService    = Depends(get_incident_service),
    copilot:          AICopilotAnalyst   = Depends(get_copilot),
) -> SOCBriefing:
    """
    AI-powered incident investigation.
    1. Fetches incident + 15-min log context from Elasticsearch.
    2. Sends enriched context to local LLM via AICopilotAnalyst.
    3. Returns structured SOC threat briefing.
    """
    logger.info(f"AI investigation triggered for incident {incident_id}")

    incident_data = await incident_service.get_incident_with_context(incident_id)
    if not incident_data:
        raise HTTPException(404, f"Incident {incident_id} not found.")

    log_count = incident_data.get("log_count", 0)
    logger.info(f"Sending {log_count} log events to AI Copilot for incident {incident_id}")

    briefing_data = await copilot.generate_investigation_summary(incident_data)
    return SOCBriefing(**briefing_data)


@router_v1.put("/{incident_id}/status")
async def update_incident_status(
    incident_id:      str,
    status:           IncidentStatus = Body(..., embed=True),
    notes:            str            = Body("",  embed=True),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    """Allows SOC analysts to manually update incident status."""
    if status == IncidentStatus.RESOLVED:
        success = await incident_service.mark_resolved(incident_id, notes=notes)
    else:
        existing = await incident_service.get_incident_with_context(incident_id)
        if not existing:
            raise HTTPException(404, f"Incident {incident_id} not found.")
        existing.pop("recent_logs", None)
        existing.pop("log_count",   None)
        existing["status"] = status
        await _elastic.upsert_incident(incident_id, existing)
        success = True

    if not success:
        raise HTTPException(500, "Failed to update incident status.")
    return {"incident_id": incident_id, "new_status": status, "updated": True}


@router_v1.post("/{incident_id}/containment/reset")
async def reset_containment(
    incident_id:      str,
    incident_service: IncidentService              = Depends(get_incident_service),
    risk_manager:     ProgressiveContainmentManager = Depends(get_risk_manager),
) -> dict:
    """Resets progressive containment after analyst confirms false positive."""
    incident = await incident_service.get_incident_with_context(incident_id)
    if not incident:
        raise HTTPException(404, f"Incident {incident_id} not found.")

    ip  = incident.get("source_ip")
    app = incident.get("app_name")
    if not ip or not app:
        raise HTTPException(400, "Incident missing source_ip or app_name.")

    await risk_manager.reset_ip(ip, app)
    await incident_service.update_containment_status(incident_id, ContainmentStatus.NONE)

    logger.info(f"Containment reset for {ip}:{app} on incident {incident_id}.")
    return {
        "incident_id":       incident_id,
        "ip_address":        ip,
        "app_name":          app,
        "containment_reset": True,
    }


@router_v1.get("/ip/{ip_address}/status")
async def get_ip_containment_status(
    ip_address: str,
    app_name:   str                          = Query(..., description="Application name"),
    risk_manager: ProgressiveContainmentManager = Depends(get_risk_manager),
) -> dict:
    """Returns current containment state for an IP+app combination."""
    return await risk_manager.get_ip_status(ip_address, app_name)
