"""
services/incident_service.py

Responsible for grouping individual anomaly events into coherent Incidents.

Why group into incidents vs. alerting on every anomaly:
- A single attack chain (port scan → brute force → data exfil) produces
  hundreds of individual anomaly events. Alerting on each creates noise
  that masks the actual threat narrative.
- Incident grouping by (IP + app + time window) lets SOC analysts see the
  full attack progression in one view rather than hunting through alerts.
- Deterministic incident IDs (based on IP+app+date) enable upsert operations
  so duplicate events update existing incidents rather than creating duplicates.
"""

import hashlib
import logging
from datetime import datetime, date
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.integrations.elastic_client import ElasticClient
from app.models.schemas import (
    AnomalyResult,
    ContainmentStatus,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
    RiskLevel,
)

logger = logging.getLogger(__name__)


def _determine_risk_level(anomaly_count: int, max_confidence: float) -> RiskLevel:
    """
    Maps anomaly count and confidence to a risk level.

    Risk levels are used for SOC dashboard prioritization — CRITICAL incidents
    appear at the top of analyst queues regardless of age.

    Thresholds chosen to align with progressive containment tiers:
    - LOW: 1 anomaly (warning tier)
    - MEDIUM: 2 anomalies or high confidence
    - HIGH: 3-4 anomalies (soft limit tier)  
    - CRITICAL: 5+ anomalies (hard block tier)
    """
    if anomaly_count >= 5 or (anomaly_count >= 3 and max_confidence >= 0.85):
        return RiskLevel.CRITICAL
    elif anomaly_count >= 3:
        return RiskLevel.HIGH
    elif anomaly_count >= 2 or max_confidence >= 0.75:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


def generate_incident_id(ip_address: str, app_name: str, incident_date: date) -> str:
    """
    Generates a deterministic incident ID.
    Same IP+app on the same day always produces the same ID, enabling
    upsert operations and preventing duplicate incidents in Elasticsearch.
    """
    raw = f"{ip_address}:{app_name}:{incident_date.isoformat()}"
    return f"INC-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"


class IncidentService:
    """
    Manages the incident lifecycle: creation, enrichment, and status transitions.
    Acts as the coordinator between the anomaly detector, risk manager, and
    Elasticsearch storage.
    """

    def __init__(self, elastic_client: ElasticClient) -> None:
        self._es = elastic_client

    async def process_anomaly_event(
        self,
        ip_address: str,
        app_name: str,
        anomaly_result: Dict[str, Any],
        raw_log: Dict[str, Any],
    ) -> Optional[IncidentResponse]:
        """
        Called each time the anomaly engine flags a log event.
        Creates or updates the corresponding incident in Elasticsearch.

        Returns the updated IncidentResponse for downstream processing
        (e.g., triggering risk containment evaluation).
        """
        if not anomaly_result.get("is_anomaly"):
            return None

        incident_id = generate_incident_id(
            ip_address, app_name, datetime.utcnow().date()
        )
        now = datetime.utcnow()

        # Try to load existing incident (upsert pattern)
        existing = await self._es.get_incident(incident_id)

        if existing:
            # Update existing incident
            anomaly_count = existing.get("anomaly_count", 0) + 1
            max_confidence = max(
                existing.get("max_confidence", 0),
                anomaly_result.get("confidence", 0),
            )
            risk_level = _determine_risk_level(anomaly_count, max_confidence)

            updated_data = {
                **existing,
                "anomaly_count": anomaly_count,
                "risk_level": risk_level,
                "last_seen": now.isoformat(),
                "status": IncidentStatus.INVESTIGATING
                if anomaly_count >= 3
                else IncidentStatus.OPEN,
            }
            # Remove incident_id from stored data (it's the ES document ID)
            updated_data.pop("incident_id", None)
            await self._es.upsert_incident(incident_id, updated_data)

            logger.info(
                f"Updated incident {incident_id}: count={anomaly_count}, risk={risk_level}"
            )
            return IncidentResponse(incident_id=incident_id, **updated_data)

        else:
            # Create new incident
            anomaly_count = 1
            confidence = anomaly_result.get("confidence", 0)
            risk_level = _determine_risk_level(anomaly_count, confidence)

            new_incident_data = {
                "source_ip": ip_address,
                "app_name": app_name,
                "risk_level": risk_level,
                "anomaly_count": anomaly_count,
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "status": IncidentStatus.OPEN,
                "containment_status": ContainmentStatus.NONE,
                "created_at": now.isoformat(),
                "max_confidence": confidence,
            }

            await self._es.upsert_incident(incident_id, new_incident_data)
            logger.info(
                f"Created incident {incident_id} for IP {ip_address} on {app_name}."
            )
            return IncidentResponse(incident_id=incident_id, **new_incident_data)

    async def update_containment_status(
        self,
        incident_id: str,
        containment_status: ContainmentStatus,
    ) -> bool:
        """
        Updates an incident's containment status after the risk manager acts.
        This keeps the incident record in sync with the actual containment state.
        """
        existing = await self._es.get_incident(incident_id)
        if not existing:
            logger.warning(f"Cannot update containment for non-existent incident {incident_id}")
            return False

        existing.pop("incident_id", None)
        existing["containment_status"] = containment_status

        # Transition to CONTAINED status for hard blocks
        if containment_status == ContainmentStatus.HARD_BLOCKED:
            existing["status"] = IncidentStatus.CONTAINED

        return await self._es.upsert_incident(incident_id, existing)

    async def get_incident_with_context(
        self, incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Enriches an incident with recent log context from Elasticsearch.
        This combined payload is what gets sent to the AI Copilot for analysis.
        """
        incident = await self._es.get_incident(incident_id)
        if not incident:
            return None

        source_ip = incident.get("source_ip")
        recent_logs = []
        if source_ip:
            recent_logs = await self._es.fetch_context_for_ip(source_ip)

        return {
            **incident,
            "recent_logs": recent_logs,
            "log_count": len(recent_logs),
        }

    async def mark_resolved(self, incident_id: str, notes: str = "") -> bool:
        """
        Marks an incident as resolved after analyst review.
        Resolved incidents are retained for threat intelligence and ML retraining.
        """
        existing = await self._es.get_incident(incident_id)
        if not existing:
            return False

        existing.pop("incident_id", None)
        existing["status"] = IncidentStatus.RESOLVED
        existing["resolved_at"] = datetime.utcnow().isoformat()
        existing["resolution_notes"] = notes

        return await self._es.upsert_incident(incident_id, existing)
