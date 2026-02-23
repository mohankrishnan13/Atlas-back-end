"""
api/routes_incidents.py

Incident management endpoints and the AI Copilot investigation trigger.

The /investigate endpoint is the core SOC workflow integration point:
Frontend clicks "Investigate" on an incident → this endpoint orchestrates:
  1. Fetch full incident data + 15-min log context from Elasticsearch
  2. Send enriched context to local LLM via AICopilotAnalyst
  3. Return structured SOC briefing to frontend for display

This orchestration is intentionally in the route layer because it coordinates
multiple services without containing business logic itself.
"""

import logging
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
    SOCBriefing,
    SOCBriefingRequest,
)
from app.services.incident_service import IncidentService
from app.services.risk_manager import ProgressiveContainmentManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])

# ─── Module-level singletons (initialized from main.py on startup) ────────────

_elastic: Optional[ElasticClient] = None
_copilot: Optional[AICopilotAnalyst] = None
_risk_manager: Optional[ProgressiveContainmentManager] = None
_incident_service: Optional[IncidentService] = None


def init_dependencies(
    elastic: ElasticClient,
    copilot: AICopilotAnalyst,
    risk_manager: ProgressiveContainmentManager,
) -> None:
    global _elastic, _copilot, _risk_manager, _incident_service
    _elastic = elastic
    _copilot = copilot
    _risk_manager = risk_manager
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


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    elastic: ElasticClient = Depends(get_elastic),
) -> IncidentListResponse:
    """
    Paginated list of all incidents.
    Frontend SOC table view consumes this endpoint.
    """
    result = await elastic.list_incidents(
        status=status, risk_level=risk_level, page=page, size=size
    )
    return IncidentListResponse(
        total=result["total"],
        incidents=[
            IncidentResponse(**i) for i in result["incidents"]
        ],
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> IncidentResponse:
    """Retrieve a single incident by ID."""
    data = await incident_service.get_incident_with_context(incident_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    # Strip log context from response (it's only needed for AI analysis)
    data.pop("recent_logs", None)
    data.pop("log_count", None)
    return IncidentResponse(**data)


@router.post("/{incident_id}/investigate", response_model=SOCBriefing)
async def investigate_incident(
    incident_id: str,
    request: SOCBriefingRequest = Body(default=SOCBriefingRequest(incident_id="")),
    incident_service: IncidentService = Depends(get_incident_service),
    copilot: AICopilotAnalyst = Depends(get_copilot),
) -> SOCBriefing:
    """
    AI-powered incident investigation endpoint.

    This is the primary human-AI collaboration touchpoint in ATLAS:
    1. SOC analyst clicks "Investigate" on a suspicious incident
    2. We fetch the incident + 15 minutes of raw logs for context
    3. The AI Copilot analyzes the data and returns a structured threat briefing
    4. The frontend displays: threat summary, confidence, recommended action,
       IoC indicators, and MITRE ATT&CK tactic mappings

    Why we cap context at 15 minutes: This window is calibrated to the median
    time-to-detect for modern attacks while keeping LLM token usage bounded.
    Longer windows would exceed the model's context limit and degrade output quality.

    The endpoint is intentionally slow (LLM inference takes 2-30s depending on
    hardware) — the frontend should show a loading spinner and use this async.
    """
    logger.info(f"AI investigation triggered for incident {incident_id}")

    # Step 1: Retrieve enriched incident data with log context
    incident_data = await incident_service.get_incident_with_context(incident_id)
    if not incident_data:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} not found. Cannot initiate AI investigation.",
        )

    log_count = incident_data.get("log_count", 0)
    logger.info(
        f"Sending {log_count} log events to AI Copilot for incident {incident_id}"
    )

    # Step 2: Send to LLM Copilot for analysis
    briefing_data = await copilot.generate_investigation_summary(incident_data)

    # Step 3: Return structured SOC briefing
    return SOCBriefing(**briefing_data)


@router.put("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    status: IncidentStatus = Body(..., embed=True),
    notes: str = Body("", embed=True),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    """
    Allows SOC analysts to manually update incident status (e.g., mark resolved).
    Audit trail: status changes are preserved in the ES document history.
    """
    if status == IncidentStatus.RESOLVED:
        success = await incident_service.mark_resolved(incident_id, notes=notes)
    else:
        existing = await incident_service.get_incident_with_context(incident_id)
        if not existing:
            raise HTTPException(404, f"Incident {incident_id} not found.")
        existing.pop("recent_logs", None)
        existing.pop("log_count", None)
        existing["status"] = status
        from app.integrations.elastic_client import ElasticClient
        await _elastic.upsert_incident(incident_id, existing)
        success = True

    if not success:
        raise HTTPException(500, "Failed to update incident status.")
    return {"incident_id": incident_id, "new_status": status, "updated": True}


@router.post("/{incident_id}/containment/reset")
async def reset_containment(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
    risk_manager: ProgressiveContainmentManager = Depends(get_risk_manager),
) -> dict:
    """
    Resets progressive containment for an IP after analyst confirms false positive
    or after remediation is complete. This lifts rate limits and unblocks IPs.
    """
    incident = await incident_service.get_incident_with_context(incident_id)
    if not incident:
        raise HTTPException(404, f"Incident {incident_id} not found.")

    ip = incident.get("source_ip")
    app = incident.get("app_name")

    if not ip or not app:
        raise HTTPException(400, "Incident missing source_ip or app_name.")

    await risk_manager.reset_ip(ip, app)
    await incident_service.update_containment_status(incident_id, ContainmentStatus.NONE)

    logger.info(f"Containment reset for {ip}:{app} by analyst action on incident {incident_id}.")
    return {
        "incident_id": incident_id,
        "ip_address": ip,
        "app_name": app,
        "containment_reset": True,
    }


@router.get("/ip/{ip_address}/status")
async def get_ip_containment_status(
    ip_address: str,
    app_name: str = Query(..., description="Application name"),
    risk_manager: ProgressiveContainmentManager = Depends(get_risk_manager),
) -> dict:
    """
    Returns current containment state for an IP+app combination.
    Used by API Gateway integration to check rate limit / block status.
    """
    return await risk_manager.get_ip_status(ip_address, app_name)
