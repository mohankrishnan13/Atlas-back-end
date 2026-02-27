"""
middleware/logging.py

BUG FIX APPLIED:
- [FIX #3] The original code called add_data_collection_middleware() at module
  import time (before lifespan ran), so elastic_client and redis_client were
  still None and the middleware was never registered.

  Fix: The middleware now reads clients from request.app.state rather than
  capturing them at construction time. Clients are set on app.state inside
  the lifespan context manager (after they are fully initialised), and the
  middleware is registered once at app-build time — before lifespan — using
  a lightweight lazy-accessor pattern.

  This is the canonical Starlette pattern for middleware that depends on
  resources that are not available until startup.
"""

import time
import uuid
import logging
from typing import Callable
from datetime import datetime

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Paths that should NOT be logged to avoid flooding ES with health-check noise.
_SKIP_LOG_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json"}


class DataCollectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for real-time API metrics collection.

    Clients (ElasticClient, RedisClient) are retrieved lazily from
    request.app.state on every request, rather than being injected at
    construction time.  This means the middleware can be registered before
    the lifespan runs (the correct Starlette ordering) while still having
    access to fully-initialised clients once the app is running.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip noisy internal paths — avoid flooding ES index
        if request.url.path in _SKIP_LOG_PATHS:
            return await call_next(request)

        # FIX #3 — lazy access via app.state; both clients may be None if
        # ES/Redis are unavailable, and we degrade gracefully in each helper.
        elastic_client = getattr(request.app.state, "elastic_client", None)
        redis_client   = getattr(request.app.state, "redis_client",   None)

        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start_time  = time.time()
        client_ip   = self._get_client_ip(request)
        user_agent  = request.headers.get("user-agent", "")
        method      = request.method
        path        = request.url.path

        await self._log_request_start(
            elastic_client, request_id, client_ip, method, path, user_agent
        )

        try:
            response   = await call_next(request)
            latency_ms = round((time.time() - start_time) * 1000, 2)
            status_code = response.status_code

            await self._log_request_completion(
                elastic_client, request_id, client_ip,
                method, path, status_code, latency_ms, user_agent,
            )
            await self._update_metrics(redis_client, method, path, status_code, latency_ms)
            await self._check_anomalies(redis_client, elastic_client,
                                        client_ip, method, path, status_code, latency_ms)
            return response

        except Exception as e:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            await self._log_error(elastic_client, request_id, client_ip, method, path, str(e), latency_ms)
            raise

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    def _get_client_ip(self, request: Request) -> str:
        for header in ("x-forwarded-for", "x-real-ip"):
            val = request.headers.get(header)
            if val:
                return val.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def _log_request_start(
        self, elastic_client, request_id, client_ip, method, path, user_agent
    ) -> None:
        if not elastic_client:
            return
        try:
            await elastic_client.index_log_event({
                "@timestamp":  datetime.utcnow().isoformat(),
                "request_id":  request_id,
                "log_type":    "api_request_start",
                "source_ip":   client_ip,
                "method":      method,
                "path":        path,
                "user_agent":  user_agent,
                "app_name":    "atlas-backend",
            })
        except Exception:
            pass

    async def _log_request_completion(
        self, elastic_client, request_id, client_ip,
        method, path, status_code, latency_ms, user_agent,
    ) -> None:
        if not elastic_client:
            return
        try:
            await elastic_client.index_log_event({
                "@timestamp":  datetime.utcnow().isoformat(),
                "request_id":  request_id,
                "log_type":    "api",
                "source_ip":   client_ip,
                "method":      method,
                "path":        path,
                "status_code": status_code,
                "latency_ms":  latency_ms,
                "user_agent":  user_agent,
                "app_name":    "atlas-backend",
                "endpoint":    f"{method} {path}",
                "is_error":    status_code >= 400,
                "is_slow":     latency_ms > 1000,
            })
        except Exception:
            pass

    async def _log_error(
        self, elastic_client, request_id, client_ip, method, path, error, latency_ms
    ) -> None:
        if not elastic_client:
            return
        try:
            await elastic_client.index_log_event({
                "@timestamp":  datetime.utcnow().isoformat(),
                "request_id":  request_id,
                "log_type":    "error",
                "source_ip":   client_ip,
                "method":      method,
                "path":        path,
                "error":       error,
                "latency_ms":  latency_ms,
                "app_name":    "atlas-backend",
            })
        except Exception:
            pass

    async def _update_metrics(
        self, redis_client, method, path, status_code, latency_ms
    ) -> None:
        if not redis_client:
            return
        try:
            await redis_client.increment("requests:total")
            await redis_client.increment(f"requests:{method}")
            if status_code >= 400:
                await redis_client.increment("errors:total")
                await redis_client.increment(f"errors:{status_code}")
            await redis_client.add_to_sorted_set("latency:recent", latency_ms)
            # Keep only last 1 000 latency samples
            await redis_client.remove_from_sorted_set("latency:recent", 0, -1001)
        except Exception:
            pass

    async def _check_anomalies(
        self, redis_client, elastic_client,
        client_ip, method, path, status_code, latency_ms
    ) -> None:
        if not redis_client:
            return
        try:
            error_key   = f"ip_errors:{client_ip}"
            await redis_client.increment(error_key, expire=3600)
            error_count = await redis_client.get(error_key)

            if error_count and int(error_count) > 10:
                await self._flag_anomaly(
                    elastic_client, "high_error_rate",
                    client_ip, method, path, {"error_count": error_count},
                )
            if latency_ms > 5000:
                await self._flag_anomaly(
                    elastic_client, "slow_request",
                    client_ip, method, path, {"latency_ms": latency_ms},
                )
            suspicious_paths = ["/admin", "/api/users", "/config", "/.env"]
            if any(sp in path.lower() for sp in suspicious_paths):
                await self._flag_anomaly(
                    elastic_client, "suspicious_path",
                    client_ip, method, path, {"path": path},
                )
        except Exception:
            pass

    async def _flag_anomaly(
        self, elastic_client, anomaly_type, client_ip, method, path, details
    ) -> None:
        if not elastic_client:
            return
        try:
            await elastic_client.index_log_event({
                "@timestamp":   datetime.utcnow().isoformat(),
                "log_type":     "anomaly",
                "anomaly_type": anomaly_type,
                "source_ip":    client_ip,
                "method":       method,
                "path":         path,
                "details":      details,
                "app_name":     "atlas-backend",
                "is_anomaly":   True,
                "anomaly_score": 0.8,
            })
        except Exception:
            pass
