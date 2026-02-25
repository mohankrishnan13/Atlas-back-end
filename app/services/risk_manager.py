"""
services/risk_manager.py

Implements Progressive Risk Containment — a graduated response model where
containment severity escalates proportionally to evidence accumulation.

Why progressive rather than binary block/allow:
- Immediately blocking on the first anomaly has a high false positive rate,
  disrupting legitimate users (e.g., a developer running load tests)
- Progressive escalation gives time for corroborating evidence to accumulate
- Each tier produces signals that different systems act on:
  Tier 1 (Warning)     → SOC dashboard notification only
  Tier 2 (Soft Limit)  → API Gateway rate limit header signal
  Tier 3 (Hard Block)  → Wazuh endpoint quarantine + firewall signal

State is maintained in Redis in production. A Python dict fallback is provided
for development/testing so the service doesn't require Redis to start.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from app.core.config import get_settings
from app.integrations.wazuh_client import WazuhClient
from app.models.schemas import ContainmentAction, ContainmentStatus

logger = logging.getLogger(__name__)


class ProgressiveContainmentManager:
    """
    Tracks per-IP anomaly counts and triggers graduated containment actions.

    In production, this class should be initialized with a real Redis client.
    The in-memory dict fallback is intentionally left for dev environments —
    it doesn't persist across restarts and doesn't work in multi-replica deployments.
    """

    # Keys stored in Redis/state dict per IP+app combination:
    # "{ip}:{app}:count"     → int, anomaly count in current window
    # "{ip}:{app}:status"    → str, current containment status
    # "{ip}:{app}:first_seen" → ISO timestamp of first anomaly in window
    # "{ip}:{app}:window_end" → ISO timestamp when the count window resets

    WINDOW_DURATION_MINUTES = 60  # Count resets every hour

    def __init__(
        self,
        redis_client=None,
        wazuh_client: Optional[WazuhClient] = None,
    ) -> None:
        settings = get_settings()
        self._warn_threshold = settings.risk_warn_threshold
        self._soft_limit_threshold = settings.risk_soft_limit_threshold
        self._hard_block_threshold = settings.risk_hard_block_threshold
        self._wazuh = wazuh_client or WazuhClient()

        # Use Redis if provided, fall back to in-memory dict for dev
        self._redis = redis_client
        self._state: Dict[str, Any] = {}  # fallback for local dev

        if not self._redis:
            logger.warning(
                "ProgressiveContainmentManager running WITHOUT Redis. "
                "State will not persist across restarts and multi-replica deployments will be inconsistent."
            )

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    async def evaluate_risk(
        self, ip_address: str, app_name: str
    ) -> ContainmentAction:
        """
        Core containment logic. Called each time an anomaly is detected for an IP.

        The method:
        1. Increments the anomaly counter for this IP+app within the rolling window
        2. Evaluates which containment tier the new count falls into
        3. Executes the tier-appropriate action
        4. Returns a ContainmentAction for the incident service to record

        The rolling window prevents permanent false-positive blocks:
        if a CI/CD pipeline causes a one-time traffic spike, its anomaly count
        resets after WINDOW_DURATION_MINUTES without new anomalies.
        """
        key_prefix = f"{ip_address}:{app_name}"
        count = await self._increment_count(key_prefix)
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
        """Returns current containment state for an IP+app pair."""
        key_prefix = f"{ip_address}:{app_name}"
        count = await self._get_count(key_prefix)
        status = await self._get_status(key_prefix)
        return {
            "ip_address": ip_address,
            "app_name": app_name,
            "anomaly_count": count,
            "containment_status": status,
        }

    async def reset_ip(self, ip_address: str, app_name: str) -> bool:
        """
        Manually reset containment state for an IP — used by SOC analysts
        after confirming a false positive or completing remediation.
        """
        key_prefix = f"{ip_address}:{app_name}"
        keys = [f"{key_prefix}:count", f"{key_prefix}:status", f"{key_prefix}:window_end"]

        if self._redis:
            await self._redis.delete(*keys)
        else:
            for k in keys:
                self._state.pop(k, None)

        logger.info(f"Containment state reset for {ip_address}:{app_name} by analyst.")
        return True

    async def list_contained_ips(self) -> list:
        """Returns all IPs currently under any form of containment."""
        if self._redis:
            # scan_iter yields str keys (decode_responses=True) — no .decode() needed
            keys = []
            async for key in self._redis.scan_iter("*:status"):
                keys.append(key)
            results = []
            for key in keys:
                status = await self._redis.get(key)
                if status and status != ContainmentStatus.NONE:
                    # key format: "{ip}:{app}:status"
                    base = key.rsplit(":status", 1)[0]
                    parts = base.rsplit(":", 1)
                    if len(parts) == 2:
                        results.append({"ip": parts[0], "app": parts[1], "status": status})
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
        """
        Maps anomaly count to a containment tier.

        We only escalate — we never de-escalate within a window. An IP at hard
        block stays blocked even if subsequent events score lower. De-escalation
        requires analyst review (or window expiry) to prevent attackers from
        timing brief pauses to evade detection.
        """

        # TIER 3: Hard Block (≥5 anomalies) — most severe, escalate to Wazuh
        if anomaly_count >= self._hard_block_threshold:
            if current_status != ContainmentStatus.HARD_BLOCKED:
                await self._set_status(key_prefix, ContainmentStatus.HARD_BLOCKED)
                escalated = await self._execute_hard_block(ip_address)
                return ContainmentAction(
                    ip_address=ip_address,
                    app_name=app_name,
                    anomaly_count=anomaly_count,
                    action_taken=ContainmentStatus.HARD_BLOCKED,
                    message=(
                        f"HARD BLOCK: {anomaly_count} anomalies detected. "
                        "Endpoint quarantine triggered via Wazuh EDR. "
                        "Traffic blocked at firewall level."
                    ),
                    escalated_to_wazuh=escalated,
                )
            else:
                # Already hard blocked — just log continuation
                return ContainmentAction(
                    ip_address=ip_address,
                    app_name=app_name,
                    anomaly_count=anomaly_count,
                    action_taken=ContainmentStatus.HARD_BLOCKED,
                    message=f"HARD BLOCK maintained. Anomaly count: {anomaly_count}.",
                    escalated_to_wazuh=False,
                )

        # TIER 2: Soft Rate Limit (3-4 anomalies) — signal to API Gateway
        elif anomaly_count >= self._soft_limit_threshold:
            if current_status not in (ContainmentStatus.SOFT_LIMITED, ContainmentStatus.HARD_BLOCKED):
                await self._set_status(key_prefix, ContainmentStatus.SOFT_LIMITED)
                logger.warning(
                    f"SOFT LIMIT: {ip_address} on {app_name} — "
                    "returning rate-limit signal for API Gateway."
                )
            return ContainmentAction(
                ip_address=ip_address,
                app_name=app_name,
                anomaly_count=anomaly_count,
                action_taken=ContainmentStatus.SOFT_LIMITED,
                message=(
                    f"SOFT RATE LIMIT: {anomaly_count} anomalies. "
                    "API Gateway instructed to throttle requests. "
                    "Monitoring for escalation to Hard Block."
                ),
                escalated_to_wazuh=False,
            )

        # TIER 1: Warning (1-2 anomalies) — log and alert SOC
        elif anomaly_count >= self._warn_threshold:
            if current_status == ContainmentStatus.NONE:
                await self._set_status(key_prefix, ContainmentStatus.WARNING)
                logger.info(
                    f"WARNING: Anomaly detected for {ip_address} on {app_name}. "
                    "Logging for correlation. No active containment."
                )
            return ContainmentAction(
                ip_address=ip_address,
                app_name=app_name,
                anomaly_count=anomaly_count,
                action_taken=ContainmentStatus.WARNING,
                message=(
                    f"WARNING: {anomaly_count} anomaly detected. "
                    "Logged for SOC review. Monitoring for pattern."
                ),
                escalated_to_wazuh=False,
            )

        # Below threshold (shouldn't normally be called with count=0)
        return ContainmentAction(
            ip_address=ip_address,
            app_name=app_name,
            anomaly_count=anomaly_count,
            action_taken=ContainmentStatus.NONE,
            message="No action — below warning threshold.",
            escalated_to_wazuh=False,
        )

    async def _execute_hard_block(self, ip_address: str) -> bool:
        """
        Dispatches the hard block action to Wazuh.
        Returns True if Wazuh quarantine succeeded, False otherwise.
        In both cases the internal status is set to HARD_BLOCKED —
        even if Wazuh fails, the block signal propagates to the API gateway.
        """
        try:
            result = await self._wazuh.quarantine_agent_by_ip(ip_address)
            if result.get("success"):
                logger.critical(
                    f"HARD BLOCK EXECUTED: {ip_address} quarantined via Wazuh. "
                    f"Agent: {result.get('agent_name')}"
                )
                return True
            else:
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
        count_key = f"{key_prefix}:count"
        window_key = f"{key_prefix}:window_end"

        if self._redis:
            # Check if window expired
            window_end = await self._redis.get(window_key)
            if window_end:
                # decode_responses=True means window_end is already a str — no .decode() needed
                window_end_dt = datetime.fromisoformat(window_end)
                if datetime.utcnow() > window_end_dt:
                    await self._redis.delete(count_key, window_key, f"{key_prefix}:status")

            count = await self._redis.incr(count_key)
            if count == 1:
                # First anomaly in window — set expiry on both the count key and window marker
                window_end_dt = datetime.utcnow() + timedelta(minutes=self.WINDOW_DURATION_MINUTES)
                await self._redis.set(window_key, window_end_dt.isoformat())
                await self._redis.expire(count_key, self.WINDOW_DURATION_MINUTES * 60)
            return int(count)
        else:
            # In-memory fallback
            window_key_full = f"{key_prefix}:window_end"
            window_end = self._state.get(window_key_full)
            if window_end and datetime.utcnow() > datetime.fromisoformat(window_end):
                # Window expired — reset
                self._state.pop(f"{key_prefix}:count", None)
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
        count_key = f"{key_prefix}:count"
        if self._redis:
            val = await self._redis.get(count_key)
            return int(val) if val else 0
        return int(self._state.get(count_key, 0))

    async def _get_status(self, key_prefix: str) -> str:
        status_key = f"{key_prefix}:status"
        if self._redis:
            # decode_responses=True — value is already a str, no .decode() needed
            val = await self._redis.get(status_key)
            return val if val else ContainmentStatus.NONE
        return self._state.get(status_key, ContainmentStatus.NONE)

    async def _set_status(self, key_prefix: str, status: ContainmentStatus) -> None:
        status_key = f"{key_prefix}:status"
        if self._redis:
            # RedisClient.set() uses `expire` param, not `ex`
            await self._redis.set(
                status_key,
                status,
                expire=self.WINDOW_DURATION_MINUTES * 60,
            )
        else:
            self._state[status_key] = status
