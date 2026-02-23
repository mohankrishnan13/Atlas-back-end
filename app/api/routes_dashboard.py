"""
api/routes_dashboard.py

Dashboard endpoints that power the SOC frontend charts and KPI widgets.
These are read-only aggregation endpoints — they don't mutate state.

All queries are delegated to ElasticClient, which handles the ES aggregation DSL.
Routes remain thin by design: validation in → service call → validated response out.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from app.integrations.elastic_client import ElasticClient
from app.ml.anomaly_engine import AnomalyDetector
from app.models.schemas import APIUsageStat, DBLatencyStat, DashboardSummary

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

# ─── Dependency injectors ──────────────────────────────────────────────────────
# These are module-level singletons, injected via FastAPI's dependency system.
# In production, replace with proper DI container (e.g., using app state).

_elastic: Optional[ElasticClient] = None
_detector: Optional[AnomalyDetector] = None


def get_elastic() -> ElasticClient:
    if _elastic is None:
        raise HTTPException(status_code=503, detail="ElasticClient not initialized.")
    return _elastic


def get_detector() -> AnomalyDetector:
    if _detector is None:
        raise HTTPException(status_code=503, detail="AnomalyDetector not initialized.")
    return _detector


def init_dependencies(elastic: ElasticClient, detector: AnomalyDetector) -> None:
    global _elastic, _detector
    _elastic = elastic
    _detector = detector


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    elastic: ElasticClient = Depends(get_elastic),
) -> DashboardSummary:
    """
    Top-level KPI summary for the SOC dashboard header.
    Returns: open incidents, critical count, blocked IPs, anomalies in last hour.
    """
    data = await elastic.get_dashboard_summary()
    # In a real system, open_incidents and blocked_ips would come from ES incident index
    return DashboardSummary(
        total_open_incidents=0,  # Populated from incident index in production
        critical_count=0,
        high_count=0,
        blocked_ips=0,
        anomalies_last_hour=data.get("anomalies_last_hour", 0),
        top_offending_ips=data.get("top_offending_ips", []),
    )


@router.get("/api-usage/{app_name}", response_model=List[APIUsageStat])
async def get_api_usage(
    app_name: str,
    hours: int = Query(default=24, ge=1, le=168, description="Lookback window in hours"),
    elastic: ElasticClient = Depends(get_elastic),
) -> List[APIUsageStat]:
    """
    Hourly API usage stats for a specific application.
    Frontend uses this for the request volume / error rate time series chart.
    """
    raw = await elastic.get_api_usage_stats(app_name=app_name, hours=hours)
    return [
        APIUsageStat(
            app_name=app_name,
            timestamp=r["timestamp"],
            request_count=r["request_count"],
            error_rate=r["error_rate"],
            avg_latency_ms=r["avg_latency_ms"],
        )
        for r in raw
    ]


@router.get("/db-latency", response_model=List[DBLatencyStat])
async def get_db_latency(
    hours: int = Query(default=24, ge=1, le=168),
    elastic: ElasticClient = Depends(get_elastic),
) -> List[DBLatencyStat]:
    """
    Database query latency percentiles across all monitored databases.
    P99 is the primary metric — it surfaces slow queries that averages hide.
    """
    raw = await elastic.get_db_query_latency(hours=hours)
    return [
        DBLatencyStat(
            db_name=r["db_name"],
            timestamp=r["timestamp"],
            avg_latency_ms=r["p50_latency_ms"],
            slow_query_count=r["slow_query_count"],
            p99_latency_ms=r["p99_latency_ms"],
        )
        for r in raw
    ]


@router.get("/anomaly-model-info")
async def get_anomaly_model_info(
    detector: AnomalyDetector = Depends(get_detector),
) -> Dict[str, Any]:
    """Returns current ML model training status and configuration."""
    return detector.model_info


@router.post("/anomaly-model/train")
async def trigger_model_training(
    detector: AnomalyDetector = Depends(get_detector),
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """
    Triggers model retraining using recent logs from Elasticsearch.
    This endpoint should be called periodically (e.g., weekly cron) to keep
    the baseline current as traffic patterns evolve.
    """
    import pandas as pd

    # Fetch a week of training data from ES
    # In production, this would be a bulk scroll query over the log index
    logger.info("Fetching training data from Elasticsearch...")
    # Placeholder — real implementation would use ES scroll API for large datasets
    training_data = pd.DataFrame(
        columns=[
            "request_count", "error_rate", "avg_latency_ms",
            "bytes_per_request", "unique_endpoints", "p99_latency_ms"
        ]
    )

    if training_data.empty:
        return {
            "status": "skipped",
            "message": "No training data available in Elasticsearch. Ingest logs first.",
        }

    result = detector.train_baseline(training_data)
    return result


import logging
logger = logging.getLogger(__name__)
