"""
services/risk_manager.py

Implements Progressive Risk Containment — a graduated response model where
containment severity escalates proportionally to evidence accumulation.

BUG FIX APPLIED:
- [FIX #4] Removed `.decode()` calls in list_contained_ips().
  The Redis client is initialised with `decode_responses=True`, which means
  all keys and values are already returned as plain Python str objects.
  Calling `.decode()` on a str raises AttributeError at runtime.

Why progressive rather than binary block/allow:
- Tier 1 (Warning)     → SOC dashboard notification only
- Tier 2 (Soft Limit)  → API Gateway rate-limit header signal
- Tier 3 (Hard Block)  → Wazuh endpoint quarantine + firewall signal
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.integrations.wazuh_client import WazuhClient
from app.models.schemas import ContainmentAction, ContainmentStatus

logger = logging.getLogger(__name__)


class ProgressiveContainmentManager:
    """
    Tracks per-IP anomaly counts and triggers graduated containment actions.
    State is kept in Redis (production) or an in-memory dict (dev fallback).
    """

    WINDOW_DURATION_MINUTES = 60

    def __init__(
        self,
        redis_client=None,
        wazuh_client: Optional[WazuhClient] = None,
    ) -> None:
        settings = get_settings()
        self._warn_threshold       = settings.risk_warn_threshold
        self._soft_limit_threshold = settings.risk_soft_limit_threshold
        self._hard_block_threshold = settings.risk_hard_block_threshold
        self._wazuh                = wazuh_client or WazuhClient()
        self._redis                = redis_client
        self._state: Dict[str, Any] = {}          # in-memory fallback for dev

        if not self._redis:
            logger.warning(
                "ProgressiveContainmentManager running WITHOUT Redis. "
                "State will not persist across restarts."
            )

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    async def evaluate_risk(
        self, ip_address: str, app_name: str
    ) -> ContainmentAction:
        key_prefix     = f"{ip_address}:{app_name}"
        count          = await self._increment_count(key_prefix)
        current_status = await self._get_status(key_prefix)

        action = await self._determine_action(
            ip_address=ip_address,
            app_name=app_name,
            anomaly_count=count,
            current_status=current_status,
            key_prefix=key_prefix,
        )
        logger.info(
            f"Risk evaluation | IP: {ip_address} | App: {app_name} | "
            f"Count: {count} | Action: {action.action_taken}"
        )
        return action

    async def get_ip_status(
        self, ip_address: str, app_name: str
    ) -> Dict[str, Any]:
        key_prefix = f"{ip_address}:{app_name}"
        return {
            "ip_address":        ip_address,
            "app_name":          app_name,
            "anomaly_count":     await self._get_count(key_prefix),
            "containment_status": await self._get_status(key_prefix),
        }

    async def reset_ip(self, ip_address: str, app_name: str) -> bool:
        key_prefix = f"{ip_address}:{app_name}"
        keys = [
            f"{key_prefix}:count",
            f"{key_prefix}:status",
            f"{key_prefix}:window_end",
        ]
        if self._redis:
            await self._redis.delete(*keys)
        else:
            for k in keys:
                self._state.pop(k, None)
        logger.info(f"Containment state reset for {ip_address}:{app_name}.")
        return True

    async def list_contained_ips(self) -> List[Dict[str, Any]]:
        """Returns all IPs currently under any form of containment."""
        if self._redis:
            results = []
            # FIX #4 — decode_responses=True makes all Redis values plain str.
            # The previous code called key.decode() which raised AttributeError
            # because str objects don't have a .decode() method.
            async for key in self._redis.scan_iter("*:status"):
                # key is already a str — no .decode() needed
                status = await self._redis.get(key)
                if status and status != ContainmentStatus.NONE:
                    # key format: "{ip}:{app}:status"
                    base = key.rsplit(":status", 1)[0]
                    parts = base.rsplit(":", 1)
                    if len(parts) == 2:
                        results.append({
                            "ip":     parts[0],
                            "app":    parts[1],
                            "status": status,  # also already a str — no .decode()
                        })
            return results
        else:
            return [
                {"key": k, "status": v}
                for k, v in self._state.items()
                if k.endswith(":status") and v != ContainmentStatus.NONE
            ]

    # ─────────────────────────────────────────────
    # Tier Logic
    # ─────────────────────────────────────────────

    async def _determine_action(
        self,
        ip_address: str,
        app_name: str,
        anomaly_count: int,
        current_status: str,
        key_prefix: str,
    ) -> ContainmentAction:
        if anomaly_count >= self._hard_block_threshold:
            if current_status != ContainmentStatus.HARD_BLOCKED:
                await self._set_status(key_prefix, ContainmentStatus.HARD_BLOCKED)
                escalated = await self._execute_hard_block(ip_address)
                return ContainmentAction(
                    ip_address=ip_address, app_name=app_name,
                    anomaly_count=anomaly_count,
                    action_taken=ContainmentStatus.HARD_BLOCKED,
                    message=(
                        f"HARD BLOCK: {anomaly_count} anomalies detected. "
                        "Endpoint quarantine triggered via Wazuh EDR."
                    ),
                    escalated_to_wazuh=escalated,
                )
            return ContainmentAction(
                ip_address=ip_address, app_name=app_name,
                anomaly_count=anomaly_count,
                action_taken=ContainmentStatus.HARD_BLOCKED,
                message=f"HARD BLOCK maintained. Anomaly count: {anomaly_count}.",
                escalated_to_wazuh=False,
            )

        elif anomaly_count >= self._soft_limit_threshold:
            if current_status not in (ContainmentStatus.SOFT_LIMITED, ContainmentStatus.HARD_BLOCKED):
                await self._set_status(key_prefix, ContainmentStatus.SOFT_LIMITED)
                logger.warning(f"SOFT LIMIT: {ip_address} on {app_name}.")
            return ContainmentAction(
                ip_address=ip_address, app_name=app_name,
                anomaly_count=anomaly_count,
                action_taken=ContainmentStatus.SOFT_LIMITED,
                message=(
                    f"SOFT RATE LIMIT: {anomaly_count} anomalies. "
                    "API Gateway instructed to throttle requests."
                ),
                escalated_to_wazuh=False,
            )

        elif anomaly_count >= self._warn_threshold:
            if current_status == ContainmentStatus.NONE:
                await self._set_status(key_prefix, ContainmentStatus.WARNING)
            return ContainmentAction(
                ip_address=ip_address, app_name=app_name,
                anomaly_count=anomaly_count,
                action_taken=ContainmentStatus.WARNING,
                message=f"WARNING: {anomaly_count} anomaly detected. Monitoring.",
                escalated_to_wazuh=False,
            )

        return ContainmentAction(
            ip_address=ip_address, app_name=app_name,
            anomaly_count=anomaly_count,
            action_taken=ContainmentStatus.NONE,
            message="No action — below warning threshold.",
            escalated_to_wazuh=False,
        )

    async def _execute_hard_block(self, ip_address: str) -> bool:
        try:
            result = await self._wazuh.quarantine_agent_by_ip(ip_address)
            if result.get("success"):
                logger.critical(
                    f"HARD BLOCK EXECUTED: {ip_address} quarantined via Wazuh. "
                    f"Agent: {result.get('agent_name')}"
                )
                return True
            logger.error(
                f"Wazuh quarantine failed for {ip_address}: {result.get('message')}. "
                "Manual firewall block may be required."
            )
            return False
        except Exception as e:
            logger.error(f"Hard block execution error for {ip_address}: {e}")
            return False

    # ─────────────────────────────────────────────
    # State Management (Redis or Dict)
    # ─────────────────────────────────────────────

    async def _increment_count(self, key_prefix: str) -> int:
        count_key  = f"{key_prefix}:count"
        window_key = f"{key_prefix}:window_end"

        if self._redis:
            window_end = await self._redis.get(window_key)
            if window_end:
                # FIX #4 — window_end is already str, no .decode() needed
                if datetime.utcnow() > datetime.fromisoformat(window_end):
                    await self._redis.delete(count_key, window_key, f"{key_prefix}:status")

            count = await self._redis.incr(count_key)
            if count == 1:
                window_end_dt = datetime.utcnow() + timedelta(minutes=self.WINDOW_DURATION_MINUTES)
                await self._redis.set(window_key, window_end_dt.isoformat())
                await self._redis.expire(count_key, self.WINDOW_DURATION_MINUTES * 60)
            return int(count)
        else:
            window_key_full = f"{key_prefix}:window_end"
            window_end      = self._state.get(window_key_full)
            if window_end and datetime.utcnow() > datetime.fromisoformat(window_end):
                self._state.pop(count_key, None)
                self._state.pop(window_key_full, None)
                self._state.pop(f"{key_prefix}:status", None)

            current = self._state.get(count_key, 0) + 1
            self._state[count_key] = current
            if current == 1:
                self._state[window_key_full] = (
                    datetime.utcnow() + timedelta(minutes=self.WINDOW_DURATION_MINUTES)
                ).isoformat()
            return current

    async def _get_count(self, key_prefix: str) -> int:
        if self._redis:
            val = await self._redis.get(f"{key_prefix}:count")
            return int(val) if val else 0
        return int(self._state.get(f"{key_prefix}:count", 0))

    async def _get_status(self, key_prefix: str) -> str:
        if self._redis:
            val = await self._redis.get(f"{key_prefix}:status")
            # FIX #4 — val is already str (decode_responses=True), not bytes
            return val if val else ContainmentStatus.NONE
        return self._state.get(f"{key_prefix}:status", ContainmentStatus.NONE)

    async def _set_status(self, key_prefix: str, status: ContainmentStatus) -> None:
        if self._redis:
            await self._redis.set(
                f"{key_prefix}:status",
                status,
                ex=self.WINDOW_DURATION_MINUTES * 60,
            )
        else:
            self._state[f"{key_prefix}:status"] = status
