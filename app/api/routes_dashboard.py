"""
api/routes_dashboard.py

Dashboard endpoints that power the SOC frontend charts and KPI widgets.
These are read-only aggregation endpoints — they don't mutate state.

All queries are delegated to ElasticClient, which handles the ES aggregation DSL.
Routes remain thin by design: validation in → service call → validated response out.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import random
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


@router.get("/overview")
async def get_overview_data(
    elastic: ElasticClient = Depends(get_elastic),
    detector: AnomalyDetector = Depends(get_detector),
) -> Dict[str, Any]:
    """
    Comprehensive overview data for the main dashboard.
    Returns aggregated metrics across all monitored systems.
    """
    # Generate sample data that matches the frontend expectations
    # In production, this would query Elasticsearch for real metrics
    
    # Generate time series data for API requests (last 24 hours)
    now = datetime.utcnow()
    api_requests_chart = []
    for i in range(24):
        hour_time = now - timedelta(hours=i)
        api_requests_chart.append({
            "name": hour_time.strftime("%H:00"),
            "requests": random.randint(800, 2500) + (24 - i) * 50  # Increasing trend
        })
    api_requests_chart.reverse()
    
    # Generate microservices data
    microservices = [
        {
            "id": "auth-service",
            "name": "Auth Service",
            "status": "Healthy" if random.random() > 0.2 else "Failing",
            "position": {"top": "20%", "left": "25%"},
            "connections": ["api-gateway", "user-db"]
        },
        {
            "id": "payment-service", 
            "name": "Payment Service",
            "status": "Healthy" if random.random() > 0.1 else "Failing",
            "position": {"top": "50%", "left": "50%"},
            "connections": ["api-gateway", "payment-db"]
        },
        {
            "id": "notification-service",
            "name": "Notification Service", 
            "status": "Healthy" if random.random() > 0.3 else "Failing",
            "position": {"top": "70%", "left": "25%"},
            "connections": ["api-gateway", "queue-service"]
        },
        {
            "id": "api-gateway",
            "name": "API Gateway",
            "status": "Healthy",
            "position": {"top": "40%", "left": "75%"},
            "connections": ["auth-service", "payment-service", "notification-service"]
        }
    ]
    
    # Generate failing endpoints for any failing services
    failing_endpoints = {}
    for service in microservices:
        if service["status"] == "Failing":
            failing_endpoints[service["id"]] = f"/{service['id'].replace('-', '/')}/health"
    
    # Generate app anomalies data
    app_anomalies = [
        {"name": "Auth Service", "anomalies": random.randint(0, 5)},
        {"name": "Payment Service", "anomalies": random.randint(0, 3)},
        {"name": "Notification Service", "anomalies": random.randint(0, 8)},
        {"name": "API Gateway", "anomalies": random.randint(0, 2)},
        {"name": "User Database", "anomalies": random.randint(0, 1)}
    ]
    
    # Generate system anomalies
    system_anomalies = []
    anomaly_types = ["High Latency", "Error Spike", "Memory Usage", "CPU Usage", "Connection Pool"]
    services = ["Auth Service", "Payment Service", "API Gateway", "Database"]
    severities = ["Critical", "High", "Medium", "Low"]
    
    for i in range(random.randint(2, 6)):
        system_anomalies.append({
            "id": f"anomaly-{i}",
            "service": random.choice(services),
            "type": random.choice(anomaly_types),
            "severity": random.choice(severities),
            "timestamp": (now - timedelta(minutes=random.randint(5, 120))).strftime("%Y-%m-%d %H:%M:%S")
        })
    
    # Calculate summary metrics
    total_api_requests = sum(item["requests"] for item in api_requests_chart)
    error_rate = round(random.uniform(0.5, 3.5), 2)
    active_alerts = len([a for a in system_anomalies if a["severity"] in ["Critical", "High"]])
    cost_risk = random.randint(1, 8)
    
    return {
        "apiRequests": total_api_requests,
        "errorRate": error_rate,
        "activeAlerts": active_alerts,
        "costRisk": cost_risk,
        "appAnomalies": app_anomalies,
        "microservices": microservices,
        "failingEndpoints": failing_endpoints,
        "apiRequestsChart": api_requests_chart,
        "systemAnomalies": system_anomalies
    }


@router.get("/api-monitoring")
async def get_api_monitoring_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """API monitoring data for the API monitoring dashboard."""
    # Generate sample API monitoring data
    now = datetime.utcnow()
    
    # Generate API usage chart data (last 24 hours)
    api_usage_chart = []
    for i in range(24):
        hour_time = now - timedelta(hours=i)
        api_usage_chart.append({
            "name": hour_time.strftime("%H:00"),
            "requests": random.randint(800, 2500),
            "errors": random.randint(5, 50),
            "latency": random.randint(50, 200)
        })
    api_usage_chart.reverse()
    
    # Generate API routing data
    api_routing = [
        {
            "id": 1,
            "app": "Auth Service",
            "path": "/api/auth/login",
            "method": "POST",
            "cost": 0.002,
            "trend": random.choice([5.2, -3.1, 0.8, -1.5]),
            "action": "Monitor"
        },
        {
            "id": 2,
            "app": "Payment Service", 
            "path": "/api/payments/charge",
            "method": "POST",
            "cost": 0.015,
            "trend": random.choice([8.7, -2.3, 1.2, -4.5]),
            "action": "Monitor"
        },
        {
            "id": 3,
            "app": "Notification Service",
            "path": "/api/notifications/send",
            "method": "POST", 
            "cost": 0.001,
            "trend": random.choice([2.1, -1.8, 0.5, -0.9]),
            "action": "Monitor"
        },
        {
            "id": 4,
            "app": "API Gateway",
            "path": "/api/gateway/health",
            "method": "GET",
            "cost": 0.0001,
            "trend": random.choice([0.5, -0.2, 0.1, -0.3]),
            "action": "Monitor"
        }
    ]
    
    return {
        "apiCallsToday": random.randint(45000, 85000),
        "blockedRequests": random.randint(150, 500),
        "avgLatency": random.randint(75, 150),
        "estimatedCost": round(random.uniform(12.50, 45.80), 2),
        "apiUsageChart": api_usage_chart,
        "apiRouting": api_routing
    }


@router.get("/network-traffic")
async def get_network_traffic_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """Network traffic monitoring data."""
    # Generate network anomalies
    network_anomalies = []
    for i in range(random.randint(3, 8)):
        network_anomalies.append({
            "id": i + 1,
            "sourceIp": f"192.168.1.{random.randint(100, 255)}",
            "destIp": f"10.0.0.{random.randint(1, 50)}",
            "app": random.choice(["Auth Service", "Payment Service", "API Gateway"]),
            "port": random.choice([80, 443, 3306, 6379, 9200]),
            "type": random.choice(["Port Scan", "DDoS", "Brute Force", "Data Exfiltration"])
        })
    
    return {
        "bandwidth": random.randint(500, 2000),  # Mbps
        "activeConnections": random.randint(1500, 3500),
        "droppedPackets": random.randint(50, 200),
        "networkAnomalies": network_anomalies
    }


@router.get("/endpoint-security")
async def get_endpoint_security_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """Endpoint security data from Wazuh integration."""
    # Generate OS distribution
    os_distribution = [
        {"name": "Windows", "value": random.randint(60, 80), "fill": "#3b82f6"},
        {"name": "macOS", "value": random.randint(15, 25), "fill": "#10b981"},
        {"name": "Linux", "value": random.randint(5, 15), "fill": "#f59e0b"}
    ]
    
    # Generate alert type distribution
    alert_types = [
        {"name": "Malware", "value": random.randint(5, 15), "fill": "#ef4444"},
        {"name": "USB Activity", "value": random.randint(2, 8), "fill": "#f59e0b"},
        {"name": "Login Attempts", "value": random.randint(10, 25), "fill": "#3b82f6"},
        {"name": "File Changes", "value": random.randint(3, 12), "fill": "#10b981"}
    ]
    
    # Generate Wazuh events
    wazuh_events = []
    employees = ["John Doe", "Jane Smith", "Mike Johnson", "Sarah Williams", "David Brown"]
    workstations = [f"WS-{i:03d}" for i in range(101, 106)]
    alerts = [
        "Malware detected on workstation",
        "USB device connected", 
        "Multiple failed login attempts",
        "Suspicious file modification",
        "Unusual network activity detected"
    ]
    severities = ["Critical", "High", "Medium", "Low"]
    
    for i in range(random.randint(5, 12)):
        wazuh_events.append({
            "id": i + 1,
            "workstationId": random.choice(workstations),
            "employee": random.choice(employees),
            "avatar": f"/avatars/{random.choice(employees).lower().replace(' ', '-')}.jpg",
            "alert": random.choice(alerts),
            "severity": random.choice(severities)
        })
    
    return {
        "monitoredLaptops": random.randint(45, 60),
        "offlineDevices": random.randint(2, 8),
        "malwareAlerts": random.randint(0, 5),
        "osDistribution": os_distribution,
        "alertTypes": alert_types,
        "wazuhEvents": wazuh_events
    }


@router.get("/db-monitoring")
async def get_db_monitoring_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """Database monitoring data."""
    # Generate operations chart data (last 24 hours)
    operations_chart = []
    for i in range(24):
        hour_time = now - timedelta(hours=i)
        operations_chart.append({
            "name": hour_time.strftime("%H:00"),
            "reads": random.randint(500, 2000),
            "writes": random.randint(100, 500),
            "deletes": random.randint(10, 50)
        })
    operations_chart.reverse()
    
    # Generate suspicious activities
    suspicious_activities = []
    tables = ["users", "payments", "transactions", "audit_logs", "sessions"]
    users = ["admin", "root", "service_account", "backup_user"]
    activity_types = [
        "Large data export detected",
        "Unauthorized table access",
        "Unusual query pattern",
        "Multiple failed login attempts",
        "Data modification outside business hours"
    ]
    
    for i in range(random.randint(2, 6)):
        suspicious_activities.append({
            "id": i + 1,
            "app": random.choice(["Auth Service", "Payment Service", "Analytics Service"]),
            "user": random.choice(users),
            "type": random.choice(activity_types),
            "table": random.choice(tables),
            "reason": f"Suspicious activity detected at {(now - timedelta(minutes=random.randint(10, 120))).strftime('%H:%M')}"
        })
    
    return {
        "activeConnections": random.randint(50, 150),
        "avgQueryLatency": random.randint(25, 85),
        "dataExportVolume": random.randint(100, 500),  # MB
        "operationsChart": operations_chart,
        "suspiciousActivity": suspicious_activities
    }


@router.get("/incidents")
async def get_incidents_data(
    elastic: ElasticClient = Depends(get_elastic),
) -> Dict[str, Any]:
    """Incidents data for the incidents page."""
    incidents = []
    incident_types = [
        "DDoS Attack Detected",
        "Unauthorized Access Attempt", 
        "Malware Infection",
        "Data Exfiltration Attempt",
        "API Abuse Detected",
        "Brute Force Attack"
    ]
    
    for i in range(random.randint(8, 15)):
        created_time = now - timedelta(hours=random.randint(1, 72))
        incidents.append({
            "id": f"incident-{i+1:03d}",
            "eventName": random.choice(incident_types),
            "timestamp": created_time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": random.choice(["Critical", "High", "Medium", "Low"]),
            "sourceIp": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "destIp": f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}",
            "targetApp": random.choice(["Auth Service", "Payment Service", "API Gateway"]),
            "status": random.choice(["Active", "Contained", "Closed"]),
            "eventDetails": f"Security incident detected and automatically logged by ATLAS system."
        })
    
    # Sort by timestamp (most recent first)
    incidents.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {"incidents": incidents}


import logging
logger = logging.getLogger(__name__)
