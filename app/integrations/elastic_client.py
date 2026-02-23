"""
integrations/elastic_client.py

Wraps the Elasticsearch Python client in a class to:
1. Centralize connection management (avoid creating a new client per request)
2. Provide typed, domain-specific query methods instead of raw ES DSL scattered
   across routes (DRY principle)
3. Isolate ES query logic so it can be mocked in unit tests without
   spinning up a real cluster.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from elasticsearch import AsyncElasticsearch, NotFoundError, ConnectionError
from elasticsearch.helpers import async_scan

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class ElasticClient:
    """
    Async Elasticsearch wrapper for ATLAS.
    Uses a single shared AsyncElasticsearch instance — ES client is thread-safe
    and connection-pooled, so instantiating once at startup is correct pattern.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._client = AsyncElasticsearch(
            hosts=[settings.elastic_host],
            basic_auth=(settings.elastic_username, settings.elastic_password),
            verify_certs=False,  # Disable for dev; enable in prod with CA cert
            retry_on_timeout=True,
            max_retries=3,
        )
        self._logs_index = settings.elastic_index_logs
        self._incidents_index = settings.elastic_index_incidents

    async def ping(self) -> bool:
        """Health check used at startup to verify ES connectivity."""
        try:
            return await self._client.ping()
        except ConnectionError:
            logger.error("Elasticsearch unreachable during ping.")
            return False

    async def close(self) -> None:
        """Gracefully close the connection pool on app shutdown."""
        await self._client.close()

    # ─────────────────────────────────────────────
    # Dashboard Metric Queries
    # ─────────────────────────────────────────────

    async def get_api_usage_stats(
        self, app_name: str, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Returns hourly API request counts, error rates, and avg latency for
        a given app over the last N hours.

        Uses a date_histogram aggregation rather than fetching raw logs —
        letting ES do the aggregation is orders of magnitude faster for
        high-cardinality log indices.
        """
        since = datetime.utcnow() - timedelta(hours=hours)

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"app_name.keyword": app_name}},
                        {"term": {"log_type.keyword": "api"}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]
                }
            },
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour",
                    },
                    "aggs": {
                        "total_requests": {"value_count": {"field": "status_code"}},
                        "error_requests": {
                            "filter": {"range": {"status_code": {"gte": 400}}}
                        },
                        "avg_latency": {"avg": {"field": "latency_ms"}},
                    },
                }
            },
        }

        try:
            response = await self._client.search(index=self._logs_index, body=query)
            buckets = response["aggregations"]["by_hour"]["buckets"]
            return [
                {
                    "timestamp": b["key_as_string"],
                    "request_count": b["total_requests"]["value"],
                    "error_count": b["error_requests"]["doc_count"],
                    "error_rate": round(
                        b["error_requests"]["doc_count"] / max(b["total_requests"]["value"], 1), 4
                    ),
                    "avg_latency_ms": round(b["avg_latency"]["value"] or 0, 2),
                }
                for b in buckets
            ]
        except Exception as e:
            logger.error(f"Failed to fetch API usage stats for {app_name}: {e}")
            return []

    async def get_db_query_latency(
        self, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Returns p50/p99 DB query latency per database per hour.

        We use percentiles aggregation rather than avg because DB latency
        distributions are heavily right-skewed — a handful of slow queries
        can mask real problems if you only look at averages.
        """
        since = datetime.utcnow() - timedelta(hours=hours)

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"log_type.keyword": "db"}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]
                }
            },
            "aggs": {
                "by_db": {
                    "terms": {"field": "app_name.keyword", "size": 20},
                    "aggs": {
                        "by_hour": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "calendar_interval": "hour",
                            },
                            "aggs": {
                                "latency_percentiles": {
                                    "percentiles": {
                                        "field": "latency_ms",
                                        "percents": [50, 99],
                                    }
                                },
                                "slow_queries": {
                                    "filter": {"range": {"latency_ms": {"gt": 1000}}}
                                },
                            },
                        }
                    },
                }
            },
        }

        try:
            response = await self._client.search(index=self._logs_index, body=query)
            results = []
            for db_bucket in response["aggregations"]["by_db"]["buckets"]:
                db_name = db_bucket["key"]
                for hour_bucket in db_bucket["by_hour"]["buckets"]:
                    percs = hour_bucket["latency_percentiles"]["values"]
                    results.append(
                        {
                            "db_name": db_name,
                            "timestamp": hour_bucket["key_as_string"],
                            "p50_latency_ms": round(percs.get("50.0") or 0, 2),
                            "p99_latency_ms": round(percs.get("99.0") or 0, 2),
                            "slow_query_count": hour_bucket["slow_queries"]["doc_count"],
                        }
                    )
            return results
        except Exception as e:
            logger.error(f"Failed to fetch DB latency stats: {e}")
            return []

    async def get_dashboard_summary(self) -> Dict[str, Any]:
        """
        Single-call aggregation for the top-level SOC dashboard KPIs.
        Batching these into one ES request reduces dashboard load time
        vs. making 5 separate API calls.
        """
        query = {
            "size": 0,
            "aggs": {
                "anomalies_last_hour": {
                    "filter": {
                        "bool": {
                            "must": [
                                {"term": {"is_anomaly": True}},
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": "now-1h",
                                        }
                                    }
                                },
                            ]
                        }
                    }
                },
                "top_offending_ips": {
                    "filter": {"term": {"is_anomaly": True}},
                    "aggs": {
                        "ips": {
                            "terms": {"field": "source_ip.keyword", "size": 10}
                        }
                    },
                },
            },
        }

        try:
            response = await self._client.search(index=self._logs_index, body=query)
            aggs = response["aggregations"]
            top_ips = [
                {"ip": b["key"], "anomaly_count": b["doc_count"]}
                for b in aggs["top_offending_ips"]["ips"]["buckets"]
            ]
            return {
                "anomalies_last_hour": aggs["anomalies_last_hour"]["doc_count"],
                "top_offending_ips": top_ips,
            }
        except Exception as e:
            logger.error(f"Failed to fetch dashboard summary: {e}")
            return {"anomalies_last_hour": 0, "top_offending_ips": []}

    # ─────────────────────────────────────────────
    # AI Copilot Context Fetching
    # ─────────────────────────────────────────────

    async def fetch_context_for_ip(
        self, ip_address: str, window_minutes: int = 15
    ) -> List[Dict[str, Any]]:
        """
        Fetches the last N minutes of ALL log types for a given source IP.

        Why 15 minutes: This window aligns with typical attacker lateral movement
        timelines — short enough to be actionable, long enough to capture
        multi-stage attack chains (recon → exploit → exfil). The LLM receives
        this context to reason about attack progression rather than isolated events.
        """
        since = datetime.utcnow() - timedelta(minutes=window_minutes)

        query = {
            "size": 200,  # Cap context to avoid blowing LLM token limits
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"source_ip.keyword": ip_address}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]
                }
            },
            "_source": [
                "@timestamp",
                "source_ip",
                "app_name",
                "log_type",
                "status_code",
                "latency_ms",
                "endpoint",
                "raw_message",
                "is_anomaly",
                "anomaly_score",
            ],
        }

        try:
            response = await self._client.search(index=self._logs_index, body=query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Failed to fetch context for IP {ip_address}: {e}")
            return []

    # ─────────────────────────────────────────────
    # Incident CRUD
    # ─────────────────────────────────────────────

    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single incident document by its ES document ID."""
        try:
            result = await self._client.get(
                index=self._incidents_index, id=incident_id
            )
            return {"incident_id": result["_id"], **result["_source"]}
        except NotFoundError:
            return None
        except Exception as e:
            logger.error(f"Failed to get incident {incident_id}: {e}")
            return None

    async def list_incidents(
        self,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        page: int = 1,
        size: int = 20,
    ) -> Dict[str, Any]:
        """Paginated incident listing with optional status/risk filters."""
        filters = []
        if status:
            filters.append({"term": {"status.keyword": status}})
        if risk_level:
            filters.append({"term": {"risk_level.keyword": risk_level}})

        query: Dict[str, Any] = {
            "from": (page - 1) * size,
            "size": size,
            "sort": [{"last_seen": {"order": "desc"}}],
            "query": {"bool": {"must": filters}} if filters else {"match_all": {}},
        }

        try:
            response = await self._client.search(
                index=self._incidents_index, body=query
            )
            hits = response["hits"]
            return {
                "total": hits["total"]["value"],
                "incidents": [
                    {"incident_id": h["_id"], **h["_source"]} for h in hits["hits"]
                ],
            }
        except Exception as e:
            logger.error(f"Failed to list incidents: {e}")
            return {"total": 0, "incidents": []}

    async def upsert_incident(
        self, incident_id: str, data: Dict[str, Any]
    ) -> bool:
        """
        Create or update an incident document.
        Using upsert prevents duplicate incidents for the same IP/app combination
        — the incident_service generates deterministic IDs based on IP+app+date.
        """
        try:
            await self._client.index(
                index=self._incidents_index,
                id=incident_id,
                document=data,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to upsert incident {incident_id}: {e}")
            return False

    async def index_log_event(self, log_data: Dict[str, Any]) -> bool:
        """Index a single enriched log event (with anomaly flags) into ES."""
        try:
            await self._client.index(index="atlas-logs", document=log_data)
            return True
        except Exception as e:
            logger.error(f"Failed to index log event: {e}")
            return False
