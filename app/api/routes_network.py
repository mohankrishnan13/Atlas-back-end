"""
api/routes_network.py

Network traffic monitoring endpoints powered by local log-file parsing
(Loghub Apache dataset) during the prototype phase.

Endpoint
────────
GET /api/metrics/network
    Aggregates Apache access logs into:
    - Top-5 source IP nodes (for the React network topology graph)
    - Anomaly table (excessive requests, high error rate, server errors)
    - Bandwidth / traffic summary

TODO [PRODUCTION]: Replace log_parser calls with Elasticsearch queries.
"""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from app.models.schemas import (
    NetworkAnomaly,
    NetworkMetricsResponse,
    NetworkNode,
)
from app.utils.log_parser import (
    aggregate_network_metrics,
    fetch_recent_network_logs,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/metrics", tags=["Network Metrics"])


@router.get("/network", response_model=NetworkMetricsResponse)
async def get_network_metrics(
    hours: int = Query(
        default=24,
        ge=1,
        le=168,
        description="Look-back window in hours (prototype: applied best-effort on log timestamps)",
    ),
    top_n: int = Query(
        default=5,
        ge=1,
        le=20,
        description="Number of top source IPs to include as network nodes",
    ),
) -> NetworkMetricsResponse:
    """
    Parses local Apache access logs and aggregates traffic metrics for the
    SOC Network Traffic dashboard page.

    The `nodes` array is shaped for a React-based network topology graph:
    each node represents a source IP with its request volume, data transferred,
    and an inferred health status (normal / warning / blocked).

    The `anomalies` array feeds the 'Network Anomaly Alerts' table:
    rows are sorted by severity (Critical → Low) so the worst offenders
    appear at the top of the analyst's queue.

    TODO [PRODUCTION]: Replace fetch_recent_network_logs() with an
    Elasticsearch query against the atlas-network-logs index.
    """
    try:
        # TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
        # e.g., response = elastic_client.search(index="atlas-network-logs", ...)
        raw_records = fetch_recent_network_logs(hours=hours)
    except Exception as exc:
        logger.error(f"Failed to read network logs: {exc}", exc_info=True)
        # Graceful degradation — return empty payload so the frontend doesn't crash
        return NetworkMetricsResponse(
            nodes=[],
            anomalies=[],
            bandwidth_usage={"total_bytes_mb": 0, "total_bytes": 0, "hourly_chart": []},
            summary={"total_requests": 0, "unique_ips": 0, "total_errors": 0, "error_rate": 0},
        )

    if not raw_records:
        logger.warning("No Apache log records returned — check log file path in config.")
        return NetworkMetricsResponse(
            nodes=[],
            anomalies=[],
            bandwidth_usage={"total_bytes_mb": 0, "total_bytes": 0, "hourly_chart": []},
            summary={"total_requests": 0, "unique_ips": 0, "total_errors": 0, "error_rate": 0},
        )

    aggregated = aggregate_network_metrics(raw_records, top_n=top_n)

    # ── Map dicts to Pydantic models ──────────────────────────────────────────
    nodes = [
        NetworkNode(
            id=n["id"],
            ip=n["ip"],
            request_count=n["request_count"],
            bytes_sent=n["bytes_sent"],
            status=n["status"],
            top_paths=n["top_paths"],
        )
        for n in aggregated["nodes"]
    ]

    anomalies = [
        NetworkAnomaly(
            id=a["id"],
            source_ip=a["source_ip"],
            anomaly_type=a["anomaly_type"],
            request_count=a["request_count"],
            error_count=a["error_count"],
            severity=a["severity"],
            first_seen=a["first_seen"],
            last_seen=a["last_seen"],
            sample_paths=a["sample_paths"],
        )
        for a in aggregated["anomalies"]
    ]

    logger.info(
        f"[network] Served {len(nodes)} nodes, {len(anomalies)} anomalies "
        f"from {aggregated['summary']['total_requests']} log records."
    )

    return NetworkMetricsResponse(
        nodes=nodes,
        anomalies=anomalies,
        bandwidth_usage=aggregated["bandwidth_usage"],
        summary=aggregated["summary"],
    )
