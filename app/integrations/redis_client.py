"""
Redis client for real-time metrics, caching, and temporary data storage.
Provides high-performance counters and analytics for ATLAS monitoring.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import redis.asyncio as redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class RedisClient:
    """
    Async Redis client for ATLAS real-time monitoring.
    
    Uses Redis for:
    - Real-time counters and metrics
    - Session data and caching
    - Rate limiting and security tracking
    - Temporary data storage
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._client = None
        self._host = settings.redis_host
        self._port = settings.redis_port
        self._db = settings.redis_db
        self._password = settings.redis_password

    async def connect(self) -> None:
        """Initialize Redis connection."""
        try:
            self._client = redis.Redis(
                host=self._host,
                port=self._port,
                db=self._db,
                password=self._password,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            # Test connection
            await self._client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._client = None

    async def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()

    async def is_connected(self) -> bool:
        """Check if Redis is connected."""
        if not self._client:
            return False
        try:
            await self._client.ping()
            return True
        except Exception:
            return False

    # ─────────────────────────────────────────────
    # Counter Operations
    # ─────────────────────────────────────────────

    async def increment(
        self, key: str, amount: int = 1, expire: Optional[int] = None
    ) -> Optional[int]:
        """
        Increment a counter atomically.
        
        Args:
            key: Counter key
            amount: Amount to increment (default: 1)
            expire: TTL in seconds (optional)
        
        Returns:
            New value after increment
        """
        if not self._client:
            return None
            
        try:
            pipe = self._client.pipeline()
            pipe.incrby(key, amount)
            if expire:
                pipe.expire(key, expire)
            result = await pipe.execute()
            return result[0]
        except Exception as e:
            logger.error(f"Failed to increment counter {key}: {e}")
            return None

    async def get(self, key: str) -> Optional[str]:
        """Get a value from Redis."""
        if not self._client:
            return None
            
        try:
            return await self._client.get(key)
        except Exception as e:
            logger.error(f"Failed to get key {key}: {e}")
            return None

    async def set(
        self, key: str, value: str, expire: Optional[int] = None
    ) -> bool:
        """Set a value in Redis with optional expiration."""
        if not self._client:
            return False
            
        try:
            return await self._client.set(key, value, ex=expire)
        except Exception as e:
            logger.error(f"Failed to set key {key}: {e}")
            return False

    # ─────────────────────────────────────────────
    # Sorted Set Operations (for metrics)
    # ─────────────────────────────────────────────

    async def add_to_sorted_set(
        self, key: str, score: float, member: str = None
    ) -> Optional[int]:
        """
        Add a member to a sorted set.
        
        Args:
            key: Sorted set key
            score: Score for the member
            member: Member value (defaults to timestamp)
        
        Returns:
            Number of elements added
        """
        if not self._client:
            return None
            
        if member is None:
            member = datetime.utcnow().isoformat()
            
        try:
            return await self._client.zadd(key, {member: score})
        except Exception as e:
            logger.error(f"Failed to add to sorted set {key}: {e}")
            return None

    async def remove_from_sorted_set(
        self, key: str, start: int, end: int
    ) -> Optional[int]:
        """Remove elements from a sorted set by rank."""
        if not self._client:
            return None
            
        try:
            return await self._client.zremrangebyrank(key, start, end)
        except Exception as e:
            logger.error(f"Failed to remove from sorted set {key}: {e}")
            return None

    async def get_sorted_set_range(
        self, key: str, start: int = 0, end: int = -1
    ) -> List[tuple]:
        """Get a range of elements from a sorted set."""
        if not self._client:
            return []
            
        try:
            return await self._client.zrange(key, start, end, withscores=True)
        except Exception as e:
            logger.error(f"Failed to get sorted set range {key}: {e}")
            return []

    # ─────────────────────────────────────────────
    # Hash Operations (for structured data)
    # ─────────────────────────────────────────────

    async def hash_set(self, key: str, field: str, value: str) -> bool:
        """Set a field in a hash."""
        if not self._client:
            return False
            
        try:
            return await self._client.hset(key, field, value)
        except Exception as e:
            logger.error(f"Failed to set hash field {key}.{field}: {e}")
            return False

    async def hash_get(self, key: str, field: str) -> Optional[str]:
        """Get a field from a hash."""
        if not self._client:
            return None
            
        try:
            return await self._client.hget(key, field)
        except Exception as e:
            logger.error(f"Failed to get hash field {key}.{field}: {e}")
            return None

    async def hash_get_all(self, key: str) -> Dict[str, str]:
        """Get all fields from a hash."""
        if not self._client:
            return {}
            
        try:
            return await self._client.hgetall(key)
        except Exception as e:
            logger.error(f"Failed to get hash {key}: {e}")
            return {}

    # ─────────────────────────────────────────────
    # List Operations (for queues)
    # ─────────────────────────────────────────────

    async def list_push(self, key: str, value: str) -> Optional[int]:
        """Push a value to a list (queue)."""
        if not self._client:
            return None
            
        try:
            return await self._client.lpush(key, value)
        except Exception as e:
            logger.error(f"Failed to push to list {key}: {e}")
            return None

    async def list_pop(self, key: str) -> Optional[str]:
        """Pop a value from a list (queue)."""
        if not self._client:
            return None
            
        try:
            return await self._client.rpop(key)
        except Exception as e:
            logger.error(f"Failed to pop from list {key}: {e}")
            return None

    async def list_length(self, key: str) -> Optional[int]:
        """Get the length of a list."""
        if not self._client:
            return None
            
        try:
            return await self._client.llen(key)
        except Exception as e:
            logger.error(f"Failed to get list length {key}: {e}")
            return None

    # ─────────────────────────────────────────────
    # Analytics and Metrics
    # ─────────────────────────────────────────────

    async def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current metrics from Redis.
        Used for dashboard real-time data.
        """
        if not self._client:
            return {}
            
        try:
            # Get basic counters
            total_requests = await self.get("requests:total") or "0"
            total_errors = await self.get("errors:total") or "0"
            
            # Get recent latency data
            latency_data = await self.get_sorted_set_range("latency:recent", -100, -1)
            latencies = [float(score) for _, score in latency_data]
            
            # Calculate statistics
            avg_latency = sum(latencies) / len(latencies) if latencies else 0
            p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0
            
            # Get active IPs (last hour)
            active_ips = await self._client.keys("ip_errors:*")
            
            return {
                "total_requests": int(total_requests),
                "total_errors": int(total_errors),
                "error_rate": (int(total_errors) / max(int(total_requests), 1)) * 100,
                "avg_latency_ms": round(avg_latency, 2),
                "p95_latency_ms": round(p95_latency, 2),
                "active_suspicious_ips": len(active_ips),
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get metrics summary: {e}")
            return {}

    async def get_hourly_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get hourly statistics for the last N hours.
        Uses Redis time-series data for performance.
        """
        if not self._client:
            return []
            
        try:
            stats = []
            now = datetime.utcnow()
            
            for hour_offset in range(hours):
                hour_time = now - timedelta(hours=hour_offset)
                hour_key = hour_time.strftime("stats:%Y-%m-%d-%H")
                
                # Get hourly data from hash
                hour_data = await self.hash_get_all(hour_key)
                
                if hour_data:
                    stats.append({
                        "hour": hour_time.strftime("%Y-%m-%dT%H:00:00"),
                        "requests": int(hour_data.get("requests", 0)),
                        "errors": int(hour_data.get("errors", 0)),
                        "avg_latency": float(hour_data.get("avg_latency", 0)),
                    })
                else:
                    stats.append({
                        "hour": hour_time.strftime("%Y-%m-%dT%H:00:00"),
                        "requests": 0,
                        "errors": 0,
                        "avg_latency": 0,
                    })
            
            return list(reversed(stats))  # Most recent first
            
        except Exception as e:
            logger.error(f"Failed to get hourly stats: {e}")
            return []
