"""
Middleware for real-time data collection and logging.
Captures API requests, performance metrics, and security events.
"""

import time
import uuid
from typing import Callable
from datetime import datetime

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.integrations.elastic_client import ElasticClient
from app.integrations.redis_client import RedisClient


class DataCollectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to collect real-time data for ATLAS monitoring.
    
    Captures:
    - API request metrics (latency, status codes, endpoints)
    - Network traffic patterns
    - Security events (failed auth, suspicious IPs)
    - Performance data
    """

    def __init__(self, app, elastic_client: ElasticClient, redis_client: RedisClient):
        super().__init__(app)
        self.elastic_client = elastic_client
        self.redis_client = redis_client

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate unique request ID for tracing
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Capture request start time
        start_time = time.time()
        
        # Extract request metadata
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        method = request.method
        path = request.url.path
        
        # Log request start
        await self._log_request_start(request_id, client_ip, method, path, user_agent)
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Calculate metrics
            end_time = time.time()
            latency_ms = round((end_time - start_time) * 1000, 2)
            status_code = response.status_code
            
            # Log completion with metrics
            await self._log_request_completion(
                request_id, client_ip, method, path, 
                status_code, latency_ms, user_agent
            )
            
            # Update real-time metrics in Redis
            await self._update_metrics(method, path, status_code, latency_ms)
            
            # Check for anomalies
            await self._check_anomalies(client_ip, method, path, status_code, latency_ms)
            
            return response
            
        except Exception as e:
            # Log errors
            end_time = time.time()
            latency_ms = round((end_time - start_time) * 1000, 2)
            
            await self._log_error(
                request_id, client_ip, method, path, str(e), latency_ms
            )
            
            # Re-raise the exception
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers."""
        # Check for forwarded IP first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check for real IP
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
            
        # Fall back to connection IP
        return request.client.host if request.client else "unknown"

    async def _log_request_start(
        self, request_id: str, client_ip: str, 
        method: str, path: str, user_agent: str
    ) -> None:
        """Log the start of a request."""
        log_data = {
            "@timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "log_type": "api_request_start",
            "source_ip": client_ip,
            "method": method,
            "path": path,
            "user_agent": user_agent,
            "app_name": "atlas-backend"
        }
        
        # Index to Elasticsearch asynchronously (fire and forget)
        try:
            await self.elastic_client.index_log_event(log_data)
        except Exception:
            # Don't let logging failures break the application
            pass

    async def _log_request_completion(
        self, request_id: str, client_ip: str, method: str, path: str,
        status_code: int, latency_ms: float, user_agent: str
    ) -> None:
        """Log the completion of a request with metrics."""
        log_data = {
            "@timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "log_type": "api",
            "source_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "user_agent": user_agent,
            "app_name": "atlas-backend",
            "endpoint": f"{method} {path}",
            "is_error": status_code >= 400,
            "is_slow": latency_ms > 1000  # > 1 second
        }
        
        # Index to Elasticsearch
        try:
            await self.elastic_client.index_log_event(log_data)
        except Exception:
            pass

    async def _log_error(
        self, request_id: str, client_ip: str, method: str, 
        path: str, error: str, latency_ms: float
    ) -> None:
        """Log application errors."""
        log_data = {
            "@timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "log_type": "error",
            "source_ip": client_ip,
            "method": method,
            "path": path,
            "error": error,
            "latency_ms": latency_ms,
            "app_name": "atlas-backend"
        }
        
        try:
            await self.elastic_client.index_log_event(log_data)
        except Exception:
            pass

    async def _update_metrics(
        self, method: str, path: str, status_code: int, latency_ms: float
    ) -> None:
        """Update real-time metrics in Redis."""
        try:
            # Increment request counters
            await self.redis_client.increment(f"requests:total")
            await self.redis_client.increment(f"requests:{method}")
            await self.redis_client.increment(f"requests:{path}")
            
            if status_code >= 400:
                await self.redis_client.increment(f"errors:total")
                await self.redis_client.increment(f"errors:{status_code}")
            
            # Update latency metrics
            await self.redis_client.add_to_sorted_set("latency:recent", latency_ms)
            
            # Keep only last 1000 latency measurements
            await self.redis_client.remove_from_sorted_set("latency:recent", 0, -1001)
            
        except Exception:
            pass

    async def _check_anomalies(
        self, client_ip: str, method: str, path: str, 
        status_code: int, latency_ms: float
    ) -> None:
        """Check for security and performance anomalies."""
        try:
            # Check for high error rate from IP
            error_key = f"ip_errors:{client_ip}"
            await self.redis_client.increment(error_key, expire=3600)  # 1 hour TTL
            
            error_count = await self.redis_client.get(error_key)
            if error_count and int(error_count) > 10:  # More than 10 errors in 1 hour
                await self._flag_anomaly(
                    "high_error_rate", client_ip, method, path, 
                    {"error_count": error_count}
                )
            
            # Check for slow requests
            if latency_ms > 5000:  # > 5 seconds
                await self._flag_anomaly(
                    "slow_request", client_ip, method, path,
                    {"latency_ms": latency_ms}
                )
            
            # Check for suspicious paths
            suspicious_paths = ["/admin", "/api/users", "/config", "/.env"]
            if any(sus in path.lower() for sus in suspicious_paths):
                await self._flag_anomaly(
                    "suspicious_path", client_ip, method, path,
                    {"path": path}
                )
                
        except Exception:
            pass

    async def _flag_anomaly(
        self, anomaly_type: str, client_ip: str, method: str, 
        path: str, details: dict
    ) -> None:
        """Flag an anomaly in the system."""
        anomaly_data = {
            "@timestamp": datetime.utcnow().isoformat(),
            "log_type": "anomaly",
            "anomaly_type": anomaly_type,
            "source_ip": client_ip,
            "method": method,
            "path": path,
            "details": details,
            "app_name": "atlas-backend",
            "is_anomaly": True,
            "anomaly_score": 0.8  # Default score
        }
        
        try:
            await self.elastic_client.index_log_event(anomaly_data)
        except Exception:
            pass
