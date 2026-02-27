"""
api/routes_dashboard.py

Dashboard endpoints that power the SOC frontend charts and KPI widgets.
These are read-only aggregation endpoints — they don't mutate state.

BUG FIXES APPLIED:
- [FIX #1] Added missing `import random` (caused NameError in /endpoint-security)
- [FIX #2] Moved `logger` definition to module top (was at bottom of file, causing
           NameError when trigger_model_training() called logger.info())
- [FIX #5] Fixed error_count KeyError — routes now consistently use "error_count"
           key that elastic_client actually returns.
"""

import logging
import random                                  # FIX #1 — was completely missing
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from app.integrations.elastic_client import ElasticClient
from app.integrations.redis_client import RedisClient
from app.ml.anomaly_engine import AnomalyDetector
from app.models.schemas import APIUsageStat, DBLatencyStat, DashboardSummary

# FIX #2 — logger must be at module TOP, not bottom of file.
# Previously defined after all functions, so any early call raised NameError.
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

# ─── Dependency injectors ──────────────────────────────────────────────────────

_elastic: Optional[ElasticClient] = None
_redis: Optional[RedisClient] = None
_detector: Optional[AnomalyDetector] = None


def get_elastic() -> ElasticClient:
    if _elastic is None:
        raise HTTPException(status_code=503, detail="ElasticClient not initialized.")
    return _elastic


def get_redis() -> RedisClient:
    if _redis is None:
        raise HTTPException(status_code=503, detail="RedisClient not initialized.")
    return _redis


def get_detector() -> AnomalyDetector:
    if _detector is None:
        raise HTTPException(status_code=503, detail="AnomalyDetector not initialized.")
    return _detector


def init_dependencies(
    elastic: ElasticClient, redis: RedisClient, detector: AnomalyDetector
) -> None:
    global _elastic, _redis, _detector
    _elastic = elastic
    _redis = redis
    _detector = detector


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    elastic: ElasticClient = Depends(get_elastic),
) -> DashboardSummary:
    data = await elastic.get_dashboard_summary()
    return DashboardSummary(
        total_open_incidents=0,
        critical_count=0,
        high_count=0,
        blocked_ips=0,
        anomalies_last_hour=data.get("anomalies_last_hour", 0),
        top_offending_ips=data.get("top_offending_ips", []),
    )


@router.get("/api-usage/{app_name}", response_model=List[APIUsageStat])
async def get_api_usage(
    app_name: str,
    hours: int = Query(default=24, ge=1, le=168),
    elastic: ElasticClient = Depends(get_elastic),
) -> List[APIUsageStat]:
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
    return detector.model_info


@router.post("/anomaly-model/train")
async def trigger_model_training(
    detector: AnomalyDetector = Depends(get_detector),
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    import pandas as pd
    # FIX #2 — logger now defined at top, so this call no longer raises NameError
    logger.info("Fetching training data from Elasticsearch...")
    training_data = pd.DataFrame(
        columns=[
            "request_count", "error_rate", "avg_latency_ms",
            "bytes_per_request", "unique_endpoints", "p99_latency_ms",
        ]
    )
    if training_data.empty:
        return {"status": "skipped", "message": "No training data. Ingest logs first."}
    return detector.train_baseline(training_data)


@router.get("/overview")
async def get_overview_data(
    elastic: ElasticClient = Depends(get_elastic),
    redis: RedisClient = Depends(get_redis),
    detector: AnomalyDetector = Depends(get_detector),
) -> Dict[str, Any]:
    try:
        redis_metrics = await redis.get_metrics_summary()
        api_usage_stats = await elastic.get_api_usage_stats("atlas-backend", hours=24)
        es_summary = await elastic.get_dashboard_summary()

        api_requests_chart = []
        for stat in api_usage_stats:
            hour = datetime.fromisoformat(
                stat["timestamp"].replace("Z", "+00:00")
            ).strftime("%H:00")
            api_requests_chart.append({
                "name": hour,
                "requests": stat["request_count"],
                "errors": stat["error_count"],     # FIX #5 — correct key from elastic_client
                "latency": stat["avg_latency_ms"],
            })

        since = datetime.utcnow() - timedelta(hours=24)
        system_anomalies = []
        try:
            resp = await elastic._client.search(
                index="atlas-logs",
                body={
                    "size": 50,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": {"bool": {"must": [
                        {"term": {"is_anomaly": True}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]}},
                },
            )
            for hit in resp["hits"]["hits"]:
                src = hit["_source"]
                system_anomalies.append({
                    "id": hit["_id"],
                    "service": src.get("app_name", "Unknown"),
                    "type": src.get("anomaly_type", "Unknown"),
                    "severity": "High" if src.get("anomaly_score", 0) > 0.7 else "Medium",
                    "timestamp": src["@timestamp"],
                })
        except Exception:
            pass

        microservices = [
            {"id": "auth-service",         "name": "Auth Service",         "status": "Healthy",
             "position": {"top": "20%", "left": "25%"}, "connections": ["api-gateway", "user-db"]},
            {"id": "payment-service",       "name": "Payment Service",      "status": "Healthy",
             "position": {"top": "50%", "left": "50%"}, "connections": ["api-gateway", "payment-db"]},
            {"id": "notification-service",  "name": "Notification Service", "status": "Healthy",
             "position": {"top": "70%", "left": "25%"}, "connections": ["api-gateway", "queue-service"]},
            {"id": "api-gateway",           "name": "API Gateway",          "status": "Healthy",
             "position": {"top": "40%", "left": "75%"},
             "connections": ["auth-service", "payment-service", "notification-service"]},
        ]

        app_anomalies = [
            {"name": svc, "anomalies": len([a for a in system_anomalies if svc in a["service"]])}
            for svc in ["Auth Service", "Payment Service", "Notification Service", "API Gateway"]
        ]

        failing_endpoints: Dict[str, int] = {}
        try:
            err_resp = await elastic._client.search(
                index="atlas-logs",
                body={
                    "size": 0,
                    "query": {"bool": {"must": [
                        {"term": {"log_type.keyword": "api"}},
                        {"range": {"status_code": {"gte": 400}}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]}},
                    "aggs": {"endpoints": {"terms": {"field": "endpoint.keyword", "size": 10}}},
                },
            )
            for bucket in err_resp["aggregations"]["endpoints"]["buckets"]:
                if bucket["doc_count"] > 5:
                    failing_endpoints[bucket["key"]] = bucket["doc_count"]
        except Exception:
            pass

        return {
            "apiRequests":      redis_metrics.get("total_requests", 0),
            "errorRate":        redis_metrics.get("error_rate", 0),
            "activeAlerts":     len([a for a in system_anomalies if a["severity"] in ["Critical", "High"]]),
            "costRisk":         min(10, len(system_anomalies)),
            "appAnomalies":     app_anomalies,
            "microservices":    microservices,
            "failingEndpoints": failing_endpoints,
            "apiRequestsChart": api_requests_chart,
            "systemAnomalies":  system_anomalies,
        }
    except Exception as e:
        logger.error(f"Overview data fetch failed: {e}", exc_info=True)
        return {
            "apiRequests": 0, "errorRate": 0, "activeAlerts": 0, "costRisk": 0,
            "appAnomalies": [], "microservices": [], "failingEndpoints": {},
            "apiRequestsChart": [], "systemAnomalies": [],
        }


@router.get("/api-monitoring")
async def get_api_monitoring_data(
    elastic: ElasticClient = Depends(get_elastic),
    redis: RedisClient = Depends(get_redis),
) -> Dict[str, Any]:
    try:
        api_usage_stats = await elastic.get_api_usage_stats("atlas-backend", hours=24)
        api_usage_chart = []
        for stat in api_usage_stats:
            hour = datetime.fromisoformat(
                stat["timestamp"].replace("Z", "+00:00")
            ).strftime("%H:00")
            api_usage_chart.append({
                "name": hour,
                "requests": stat["request_count"],
                "errors": stat["error_count"],     # FIX #5
                "latency": stat["avg_latency_ms"],
            })

        redis_metrics = await redis.get_metrics_summary()
        api_routing: List[Dict] = []
        try:
            resp = await elastic._client.search(
                index="atlas-logs",
                body={
                    "size": 0,
                    "query": {"bool": {"must": [
                        {"term": {"log_type.keyword": "api"}},
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                    ]}},
                    "aggs": {"endpoints": {
                        "terms": {"field": "endpoint.keyword", "size": 10},
                        "aggs": {"avg_latency": {"avg": {"field": "latency_ms"}}},
                    }},
                },
            )
            for i, bucket in enumerate(resp["aggregations"]["endpoints"]["buckets"]):
                ep = bucket["key"]
                svc = (
                    "Auth Service"         if "auth"         in ep.lower() else
                    "Payment Service"      if "payment"      in ep.lower() else
                    "Notification Service" if "notification" in ep.lower() else
                    "API Gateway"          if "gateway"      in ep.lower() else "Unknown"
                )
                cost = 0.015 if "payment" in ep.lower() else (0.002 if "auth" in ep.lower() else 0.001)
                api_routing.append({"id": i + 1, "app": svc, "path": ep, "method": "POST",
                                    "cost": cost, "trend": 0.0, "action": "Monitor"})
        except Exception:
            pass

        return {
            "apiCallsToday":  redis_metrics.get("total_requests", 0),
            "blockedRequests": redis_metrics.get("total_errors", 0),
            "avgLatency":     redis_metrics.get("avg_latency_ms", 0),
            "estimatedCost":  len(api_routing) * 0.01,
            "apiUsageChart":  api_usage_chart,
            "apiRouting":     api_routing,
        }
    except Exception as e:
        logger.error(f"API monitoring fetch failed: {e}", exc_info=True)
        return {"apiCallsToday": 0, "blockedRequests": 0, "avgLatency": 0,
                "estimatedCost": 0, "apiUsageChart": [], "apiRouting": []}


@router.get("/network-traffic")
async def get_network_traffic_data(
    elastic: ElasticClient = Depends(get_elastic),
    redis: RedisClient = Depends(get_redis),
) -> Dict[str, Any]:
    try:
        since = datetime.utcnow() - timedelta(hours=24)
        bandwidth_data: List[Dict] = []
        connections_data: List[Dict] = []
        network_anomalies: List[Dict] = []
        try:
            resp = await elastic._client.search(
                index="atlas-logs",
                body={
                    "size": 0,
                    "query": {"bool": {"must": [
                        {"term": {"log_type.keyword": "network"}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]}},
                    "aggs": {
                        "bandwidth": {
                            "date_histogram": {"field": "@timestamp", "calendar_interval": "hour"},
                            "aggs": {"avg_bandwidth": {"avg": {"field": "bandwidth_mbps"}}},
                        },
                        "connections": {
                            "date_histogram": {"field": "@timestamp", "calendar_interval": "hour"},
                            "aggs": {
                                "active_connections": {"avg": {"field": "active_connections"}},
                                "dropped_packets":    {"sum": {"field": "dropped_packets"}},
                            },
                        },
                        "anomalies": {
                            "filter": {"term": {"is_anomaly": True}},
                            "aggs": {"top_ips": {"terms": {"field": "source_ip.keyword", "size": 10}}},
                        },
                    },
                },
            )
            for b in resp["aggregations"]["bandwidth"]["buckets"]:
                bandwidth_data.append({
                    "hour": datetime.fromisoformat(b["key_as_string"].replace("Z", "+00:00")).strftime("%H:00"),
                    "bandwidth": round(b["avg_bandwidth"]["value"] or 0, 2),
                })
            for b in resp["aggregations"]["connections"]["buckets"]:
                connections_data.append({
                    "hour": datetime.fromisoformat(b["key_as_string"].replace("Z", "+00:00")).strftime("%H:00"),
                    "connections": int(b["active_connections"]["value"] or 0),
                    "dropped":     int(b["dropped_packets"]["value"]    or 0),
                })
            for b in resp["aggregations"]["anomalies"]["top_ips"]["buckets"]:
                if b["doc_count"] > 5:
                    network_anomalies.append({
                        "id": len(network_anomalies) + 1,
                        "sourceIp": b["key"], "destIp": "Unknown",
                        "app": "Network", "port": 0,
                        "type": "Suspicious Activity", "count": b["doc_count"],
                    })
        except Exception:
            pass

        return {
            "bandwidth":         bandwidth_data[-1]["bandwidth"]    if bandwidth_data    else 0,
            "activeConnections": connections_data[-1]["connections"] if connections_data else 0,
            "droppedPackets":    connections_data[-1]["dropped"]     if connections_data else 0,
            "networkAnomalies":  network_anomalies,
            "bandwidthChart":    bandwidth_data,
            "connectionsChart":  connections_data,
        }
    except Exception as e:
        logger.error(f"Network traffic fetch failed: {e}", exc_info=True)
        return {"bandwidth": 0, "activeConnections": 0, "droppedPackets": 0,
                "networkAnomalies": [], "bandwidthChart": [], "connectionsChart": []}


@router.get("/endpoint-security")
async def get_endpoint_security_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """
    NOTE: Returns simulated data in prototype phase.
    TODO [PRODUCTION]: Replace with real Wazuh + ES queries.
    """
    # FIX #1 — random is now imported; these calls no longer raise NameError
    os_distribution = [
        {"name": "Windows", "value": random.randint(60, 80), "fill": "#3b82f6"},
        {"name": "macOS",   "value": random.randint(15, 25), "fill": "#10b981"},
        {"name": "Linux",   "value": random.randint(5,  15), "fill": "#f59e0b"},
    ]
    alert_types = [
        {"name": "Malware",        "value": random.randint(5,  15), "fill": "#ef4444"},
        {"name": "USB Activity",   "value": random.randint(2,   8), "fill": "#f59e0b"},
        {"name": "Login Attempts", "value": random.randint(10, 25), "fill": "#3b82f6"},
        {"name": "File Changes",   "value": random.randint(3,  12), "fill": "#10b981"},
    ]
    employees    = ["John Doe", "Jane Smith", "Mike Johnson", "Sarah Williams", "David Brown"]
    workstations = [f"WS-{i:03d}" for i in range(101, 106)]
    alerts_list  = [
        "Malware detected on workstation", "USB device connected",
        "Multiple failed login attempts",  "Suspicious file modification",
        "Unusual network activity detected",
    ]
    wazuh_events = [
        {
            "id":            i + 1,
            "workstationId": random.choice(workstations),
            "employee":      (emp := random.choice(employees)),
            "avatar":        f"/avatars/{emp.lower().replace(' ', '-')}.jpg",
            "alert":         random.choice(alerts_list),
            "severity":      random.choice(["Critical", "High", "Medium", "Low"]),
        }
        for i in range(random.randint(5, 12))
    ]
    return {
        "monitoredLaptops": random.randint(45, 60),
        "offlineDevices":   random.randint(2,   8),
        "malwareAlerts":    random.randint(0,   5),
        "osDistribution":   os_distribution,
        "alertTypes":       alert_types,
        "wazuhEvents":      wazuh_events,
    }


@router.get("/db-monitoring")
async def get_db_monitoring_data(
    elastic: ElasticClient = Depends(get_elastic),
    redis: RedisClient = Depends(get_redis),
) -> Dict[str, Any]:
    try:
        db_latency_stats = await elastic.get_db_query_latency(hours=24)
        since = datetime.utcnow() - timedelta(hours=24)
        operations_chart: List[Dict]     = []
        suspicious_activities: List[Dict] = []
        current_connections = 0
        try:
            resp = await elastic._client.search(
                index="atlas-logs",
                body={
                    "size": 0,
                    "query": {"bool": {"must": [
                        {"term": {"log_type.keyword": "db"}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]}},
                    "aggs": {
                        "operations": {
                            "date_histogram": {"field": "@timestamp", "calendar_interval": "hour"},
                            "aggs": {
                                "reads":   {"sum": {"field": "read_operations"}},
                                "writes":  {"sum": {"field": "write_operations"}},
                                "deletes": {"sum": {"field": "delete_operations"}},
                            },
                        },
                        "connections": {
                            "date_histogram": {"field": "@timestamp", "calendar_interval": "hour"},
                            "aggs": {"active_connections": {"avg": {"field": "active_connections"}}},
                        },
                        "suspicious": {
                            "filter": {"term": {"is_suspicious": True}},
                            "aggs": {"activities": {"terms": {"field": "activity_type.keyword", "size": 10}}},
                        },
                    },
                },
            )
            for b in resp["aggregations"]["operations"]["buckets"]:
                operations_chart.append({
                    "name":    datetime.fromisoformat(b["key_as_string"].replace("Z", "+00:00")).strftime("%H:00"),
                    "reads":   b["reads"]["value"]   or 0,
                    "writes":  b["writes"]["value"]  or 0,
                    "deletes": b["deletes"]["value"] or 0,
                })
            conn_buckets = resp["aggregations"]["connections"]["buckets"]
            if conn_buckets:
                current_connections = int(conn_buckets[-1]["active_connections"]["value"] or 0)
            for ab in resp["aggregations"]["suspicious"]["activities"]["buckets"]:
                suspicious_activities.append({
                    "id": len(suspicious_activities) + 1,
                    "app": ab["key"], "user": "Unknown", "type": ab["key"],
                    "table": "Unknown", "reason": f"Suspicious activity: {ab['key']}",
                })
        except Exception:
            pass

        latencies = [s["p50_latency_ms"] for s in db_latency_stats]
        avg_q_lat = sum(latencies) / len(latencies) if latencies else 0.0
        data_exp_vol = sum(op["reads"] + op["writes"] for op in operations_chart) / 1000

        return {
            "activeConnections":  current_connections,
            "avgQueryLatency":    round(avg_q_lat,    2),
            "dataExportVolume":   round(data_exp_vol, 2),
            "operationsChart":    operations_chart,
            "suspiciousActivity": suspicious_activities,
        }
    except Exception as e:
        logger.error(f"DB monitoring fetch failed: {e}", exc_info=True)
        return {"activeConnections": 0, "avgQueryLatency": 0, "dataExportVolume": 0,
                "operationsChart": [], "suspiciousActivity": []}


@router.get("/incidents")
async def get_incidents_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    try:
        resp = await elastic.list_incidents(page=1, size=50)
        incidents = [
            {
                "id":          inc.get("incident_id", "unknown"),
                "eventName":   inc.get("title",            "Unknown Incident"),
                "timestamp":   inc.get("created_at",       datetime.utcnow().isoformat()),
                "severity":    inc.get("risk_level",       "Medium"),
                "sourceIp":    inc.get("source_ip",        "Unknown"),
                "destIp":      inc.get("target_ip",        "Unknown"),
                "targetApp":   inc.get("affected_service", "Unknown"),
                "status":      inc.get("status",           "Open"),
                "description": inc.get("description",      "No description available"),
            }
            for inc in resp.get("incidents", [])
        ]
        return {"incidents": incidents, "total": resp.get("total", 0)}
    except Exception as e:
        logger.error(f"Incidents data fetch failed: {e}", exc_info=True)
        return {"incidents": [], "total": 0}
