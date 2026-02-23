"""
integrations/wazuh_client.py

Wazuh is our endpoint detection & response (EDR) platform.
This client is invoked only at the hard block tier of progressive containment —
i.e., when an IP has triggered 5+ anomalies.

Quarantining via Wazuh is more precise than a perimeter firewall block because:
1. It operates at the agent level, catching internal lateral movement
2. It preserves forensic artifacts on the endpoint (processes, memory)
3. Actions are logged in Wazuh's own audit trail, giving SOC teams full attribution
"""

import logging
import httpx
from typing import Dict, Any, Optional
from app.core.config import get_settings

logger = logging.getLogger(__name__)


class WazuhClient:
    """
    Async REST client for the Wazuh Manager API.
    Handles JWT authentication (Wazuh tokens expire every 15 min by default)
    with automatic re-auth on 401 responses.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._base_url = settings.wazuh_api_url
        self._username = settings.wazuh_username
        self._password = settings.wazuh_password
        self._token: Optional[str] = None
        # verify=False required for self-signed certs common in Wazuh deployments
        self._http = httpx.AsyncClient(verify=False, timeout=15.0)

    async def _authenticate(self) -> bool:
        """Obtain a JWT from Wazuh Manager. Tokens are short-lived (900s default)."""
        try:
            resp = await self._http.post(
                f"{self._base_url}/security/user/authenticate",
                auth=(self._username, self._password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            logger.info("Wazuh authentication successful.")
            return True
        except Exception as e:
            logger.error(f"Wazuh authentication failed: {e}")
            return False

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def _request(
        self, method: str, path: str, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Wraps all HTTP calls with automatic re-auth on 401.
        This avoids forcing callers to handle token expiry logic.
        """
        if not self._token:
            await self._authenticate()

        try:
            resp = await self._http.request(
                method,
                f"{self._base_url}{path}",
                headers=self._auth_headers(),
                **kwargs,
            )
            if resp.status_code == 401:
                # Token expired — re-auth once and retry
                logger.info("Wazuh token expired. Re-authenticating...")
                await self._authenticate()
                resp = await self._http.request(
                    method,
                    f"{self._base_url}{path}",
                    headers=self._auth_headers(),
                    **kwargs,
                )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Wazuh API request failed [{method} {path}]: {e}")
            return None

    async def quarantine_agent_by_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Find the Wazuh agent associated with an IP and isolate it.

        Network isolation cuts off the agent from all traffic except the
        Wazuh Manager channel — preserving forensic access while preventing
        further attack progression. This is a drastic action, hence it's only
        triggered at the hard block threshold (5+ anomalies).
        """
        # Step 1: Resolve IP → Agent ID
        agent_data = await self._request(
            "GET",
            "/agents",
            params={"select": "id,name,ip,status", "ip": ip_address},
        )

        if not agent_data or not agent_data.get("data", {}).get("affected_items"):
            logger.warning(
                f"No Wazuh agent found for IP {ip_address}. "
                "Falling back to firewall block signal."
            )
            return {
                "success": False,
                "action": "no_agent_found",
                "ip": ip_address,
                "message": "No registered Wazuh agent for this IP. Signal upstream firewall.",
            }

        agent = agent_data["data"]["affected_items"][0]
        agent_id = agent["id"]
        agent_name = agent.get("name", "unknown")

        # Step 2: Isolate the agent
        isolate_result = await self._request(
            "PUT",
            f"/agents/{agent_id}/isolation",
            json={"command": "isolate"},
        )

        if isolate_result:
            logger.warning(
                f"HARD BLOCK: Quarantined agent {agent_name} (ID: {agent_id}) "
                f"for IP {ip_address} via Wazuh."
            )
            return {
                "success": True,
                "action": "quarantined",
                "agent_id": agent_id,
                "agent_name": agent_name,
                "ip": ip_address,
                "message": f"Agent {agent_name} isolated via Wazuh EDR.",
            }
        else:
            return {
                "success": False,
                "action": "quarantine_failed",
                "agent_id": agent_id,
                "ip": ip_address,
                "message": "Wazuh isolation command failed. Manual intervention required.",
            }

    async def run_active_response(
        self, agent_id: str, command: str, arguments: list = None
    ) -> Optional[Dict[str, Any]]:
        """
        Trigger a Wazuh active response script on an agent.
        Useful for custom containment actions like killing a process or
        blocking a specific port without full network isolation.
        """
        payload = {
            "command": command,
            "arguments": arguments or [],
            "alert": {"data": {"srcip": "atlas-triggered"}},
        }
        return await self._request(
            "PUT",
            f"/active-response",
            params={"agents_list": agent_id},
            json=payload,
        )

    async def close(self) -> None:
        await self._http.aclose()
