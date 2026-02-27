"""
api/routes_endpoints.py

Endpoint security monitoring router — parses Linux Syslog and Windows Event
Logs from local Loghub files during the prototype phase.

Endpoint
────────
GET /api/metrics/endpoints
    Returns the 'Active Endpoint Alerts' table consumed by the SOC
    Endpoint Security dashboard page.

TODO [PRODUCTION]: Replace log_parser calls with Wazuh + Elasticsearch queries.
"""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Query
from app.models.schemas import (
    EndpointAlert,
    EndpointMetricsResponse,
)
from app.utils.log_parser import (
    aggregate_endpoint_alerts,
    fetch_recent_syslog_events,
    fetch_recent_windows_events,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/metrics", tags=["Endpoint Security"])


@router.get("/endpoints", response_model=EndpointMetricsResponse)
async def get_endpoint_metrics(
    hours: int = Query(
        default=24,
        ge=1,
        le=168,
        description="Look-back window in hours",
    ),
    max_alerts: int = Query(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of alerts to return (sorted by severity)",
    ),
) -> EndpointMetricsResponse:
    """
    Combines Linux Syslog (SSH brute force, auth failures, sudo failures, kernel
    panics) and Windows Event Log (login failures, system errors) into a single
    unified alert feed for the SOC endpoint security page.

    Alert types classified from syslog:
        ssh_brute_force  — Failed SSH login for a known or invalid user
        ssh_invalid_user — Connection attempt for a non-existent account
        auth_failure     — PAM / pam_unix authentication failure
        sudo_auth_failure — sudo elevation failure
        system_critical  — OOM killer, kernel panic, etc.
        system_error     — Generic error / denied / refused messages

    Alert types from Windows events:
        failed_login  — Event IDs 529 / 4625 (logon failure)
        system_error  — Windows Error-level events

    Severity mapping:
        Critical → kernel panic, OOM
        High     → SSH brute force, sudo failure, Windows login failure
        Medium   → Auth failure, invalid SSH user, Windows errors
        Low      → Generic errors, warnings

    TODO [PRODUCTION]: Replace fetch_recent_syslog_events() and
    fetch_recent_windows_events() with Wazuh API queries or Elasticsearch
    queries against the atlas-syslog-* and atlas-winevent-* indices.
    """
    # ── Read from local log files ─────────────────────────────────────────────
    # TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    # e.g., response = elastic_client.search(index="atlas-syslog-*", ...)
    syslog_records: List[Dict] = []
    try:
        syslog_records = fetch_recent_syslog_events(hours=hours)
    except Exception as exc:
        logger.error(f"Syslog read failed: {exc}", exc_info=True)

    # TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    # e.g., response = elastic_client.search(index="atlas-winevent-*", ...)
    windows_records: List[Dict] = []
    try:
        windows_records = fetch_recent_windows_events(hours=hours)
    except Exception as exc:
        logger.error(f"Windows event log read failed: {exc}", exc_info=True)

    # Both sources failed — return graceful empty response
    if not syslog_records and not windows_records:
        logger.warning(
            "No endpoint log records found — check syslog/Windows log file paths."
        )
        return EndpointMetricsResponse(
            alerts=[],
            summary={"total_alerts": 0, "critical_count": 0, "high_count": 0, "affected_hosts": 0},
            auth_failure_ips=[],
        )

    # ── Aggregate into unified alert list ─────────────────────────────────────
    aggregated = aggregate_endpoint_alerts(
        syslog_records=syslog_records,
        windows_records=windows_records,
        top_n=max_alerts,
    )

    # ── Map dicts to Pydantic models ──────────────────────────────────────────
    alerts = [
        EndpointAlert(
            id=a["id"],
            workstation_id=a["workstation_id"],
            alert_type=a["alert_type"],
            source_ip=a.get("source_ip"),
            username=a.get("username"),
            message=a["message"],
            severity=a["severity"],
            timestamp=a["timestamp"],
            raw_line=a.get("raw_line"),
        )
        for a in aggregated["alerts"]
    ]

    logger.info(
        f"[endpoints] Returned {len(alerts)} endpoint alerts "
        f"({aggregated['summary']['critical_count']} Critical, "
        f"{aggregated['summary']['high_count']} High) "
        f"from {len(syslog_records)} syslog + {len(windows_records)} Windows records."
    )

    return EndpointMetricsResponse(
        alerts=alerts,
        summary=aggregated["summary"],
        auth_failure_ips=aggregated["auth_failure_ips"],
    )
