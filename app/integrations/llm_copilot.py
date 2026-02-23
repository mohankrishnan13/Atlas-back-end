"""
integrations/llm_copilot.py

The AI SOC Analyst Copilot powered by a locally-hosted LLM via Ollama.

Why local LLM instead of a cloud API (GPT-4, Claude):
- SOC data contains PII, internal infrastructure details, and active attack logs
  that should never leave the organization's network boundary.
- A local model gives SOC teams control over fine-tuning on their own threat intel.
- Zero-latency to a cloud provider means faster investigation cycles.

The system prompt is engineered to constrain the model to security analyst
reasoning patterns and force structured JSON output — preventing the LLM from
producing creative but unreliable narratives that could mislead analysts.
"""

import json
import logging
import re
from typing import Any, Dict, List
from datetime import datetime

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# System Prompt Template
# The prompt is intentionally strict to prevent hallucinations common in
# security contexts. We constrain the model to only reason from provided data
# and explicitly forbid speculative conclusions.
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are ATLAS Copilot, an expert AI SOC (Security Operations Center) Analyst.

Your role is to analyze network and application log data to identify threats and recommend containment actions.

STRICT RULES:
1. Base ALL conclusions ONLY on the log data provided. Do NOT speculate or hallucinate.
2. If log data is insufficient for a conclusion, state "Insufficient data" explicitly.
3. Your output MUST be a valid JSON object with EXACTLY these keys:
   - threat_summary (string): 2-4 sentence factual description of the observed behavior.
   - confidence_score (float): Your confidence between 0.0 and 1.0, based on evidence density.
   - recommended_action (string): ONE of: "monitor", "soft_rate_limit", "hard_block", "escalate_to_human".
   - ioc_indicators (array of strings): Specific IPs, endpoints, or patterns that are indicators of compromise.
   - mitre_tactics (array of strings): MITRE ATT&CK tactic names this behavior maps to (empty array if uncertain).

4. Do NOT include markdown, code blocks, or any text outside the JSON object.
5. recommended_action must be proportional to evidence: do not recommend hard_block without clear evidence.

Security analyst context: You are reviewing a potential security incident. The anomaly detection system has flagged this IP for deviating from established baseline behavior."""


class AICopilotAnalyst:
    """
    Sends enriched incident context to a locally-hosted Ollama LLM
    and returns a structured SOC investigation briefing.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._ollama_url = f"{settings.ollama_base_url}/api/generate"
        self._model = settings.ollama_model
        # Generous timeout — local LLMs can be slow on first token generation
        self._http = httpx.AsyncClient(timeout=120.0)

    async def generate_investigation_summary(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Core method: constructs a structured investigation prompt and calls Ollama.

        The incident_data dict is expected to contain:
        - incident_id: str
        - source_ip: str
        - app_name: str
        - anomaly_count: int
        - risk_level: str
        - recent_logs: list of log event dicts
        - anomaly_results: list of anomaly score dicts

        Returns a parsed dict matching the SOCBriefing schema.
        Falls back to a safe error response rather than raising — SOC tools
        must remain functional even when the AI component fails.
        """
        prompt = self._build_prompt(incident_data)

        try:
            response = await self._http.post(
                self._ollama_url,
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "system": SYSTEM_PROMPT,
                    "stream": False,  # We want the full response, not SSE stream
                    "options": {
                        "temperature": 0.1,      # Low temp = more deterministic, less hallucination
                        "top_p": 0.9,
                        "num_predict": 1024,
                    },
                },
            )
            response.raise_for_status()
            raw_text = response.json().get("response", "")
            return self._parse_llm_response(raw_text, incident_data)

        except httpx.TimeoutException:
            logger.error("Ollama LLM request timed out.")
            return self._fallback_response(
                incident_data, reason="LLM timeout — model may be loading or overloaded."
            )
        except Exception as e:
            logger.error(f"LLM Copilot request failed: {e}")
            return self._fallback_response(incident_data, reason=str(e))

    def _build_prompt(self, incident_data: Dict[str, Any]) -> str:
        """
        Formats incident data into a structured prompt.
        We serialize log data as compact JSON rather than English prose
        because LLMs extract structured data more reliably from structured input.
        """
        logs = incident_data.get("recent_logs", [])
        anomaly_results = incident_data.get("anomaly_results", [])

        # Summarize log distribution to avoid prompt bloat
        log_type_counts: Dict[str, int] = {}
        status_codes: Dict[str, int] = {}
        endpoints_seen: List[str] = []

        for log in logs:
            lt = log.get("log_type", "unknown")
            log_type_counts[lt] = log_type_counts.get(lt, 0) + 1
            sc = str(log.get("status_code", "N/A"))
            status_codes[sc] = status_codes.get(sc, 0) + 1
            ep = log.get("endpoint")
            if ep and ep not in endpoints_seen:
                endpoints_seen.append(ep)

        # Include the 10 most anomalous individual log entries for detail
        anomalous_logs = [
            l for l in logs if l.get("is_anomaly") or (l.get("anomaly_score", 0) or 0) < -0.1
        ][:10]

        prompt = f"""
INCIDENT INVESTIGATION REQUEST
================================
Incident ID: {incident_data.get('incident_id', 'N/A')}
Source IP: {incident_data.get('source_ip', 'N/A')}
Target Application: {incident_data.get('app_name', 'N/A')}
Anomaly Count (15-min window): {incident_data.get('anomaly_count', 0)}
Risk Level: {incident_data.get('risk_level', 'unknown')}
Analysis Window: Last 15 minutes

LOG SUMMARY (last 15 minutes):
- Total log entries: {len(logs)}
- Log type breakdown: {json.dumps(log_type_counts)}
- Status code distribution: {json.dumps(status_codes)}
- Unique endpoints accessed: {json.dumps(endpoints_seen[:20])}

ANOMALY DETECTION RESULTS:
{json.dumps(anomaly_results, default=str, indent=2)}

MOST ANOMALOUS LOG ENTRIES:
{json.dumps(anomalous_logs, default=str, indent=2)}

Based ONLY on the above data, provide your structured security analysis as a JSON object.
"""
        return prompt.strip()

    def _parse_llm_response(
        self, raw_text: str, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extracts and validates JSON from the LLM response.

        LLMs sometimes wrap JSON in markdown code fences even when instructed
        not to — we strip those defensively. If JSON parsing fails entirely,
        we return a safe fallback rather than crashing the endpoint.
        """
        # Strip potential markdown code fences
        cleaned = re.sub(r"```(?:json)?", "", raw_text).strip().strip("```").strip()

        # Find JSON object boundaries
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start == -1 or end == 0:
            logger.warning("LLM response contained no JSON object.")
            return self._fallback_response(incident_data, reason="LLM returned non-JSON output.")

        try:
            parsed = json.loads(cleaned[start:end])
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM JSON: {e}. Raw: {cleaned[start:end][:200]}")
            return self._fallback_response(incident_data, reason=f"JSON parse error: {e}")

        # Enforce schema and clamp values
        return {
            "incident_id": incident_data.get("incident_id", ""),
            "threat_summary": str(parsed.get("threat_summary", "Analysis unavailable.")),
            "confidence_score": max(0.0, min(1.0, float(parsed.get("confidence_score", 0.5)))),
            "recommended_action": parsed.get("recommended_action", "monitor"),
            "ioc_indicators": parsed.get("ioc_indicators", []),
            "mitre_tactics": parsed.get("mitre_tactics", []),
            "generated_at": datetime.utcnow().isoformat(),
            "model_used": self._model,
        }

    def _fallback_response(
        self, incident_data: Dict[str, Any], reason: str = "Unknown error"
    ) -> Dict[str, Any]:
        """
        Returns a safe, human-readable fallback when the LLM pipeline fails.
        Critical: SOC tools must never silently fail — analysts need to know
        the AI component is down so they can investigate manually.
        """
        return {
            "incident_id": incident_data.get("incident_id", ""),
            "threat_summary": (
                f"AI analysis unavailable: {reason}. "
                f"Manual review required for IP {incident_data.get('source_ip', 'N/A')} "
                f"on app {incident_data.get('app_name', 'N/A')}."
            ),
            "confidence_score": 0.0,
            "recommended_action": "escalate_to_human",
            "ioc_indicators": [],
            "mitre_tactics": [],
            "generated_at": datetime.utcnow().isoformat(),
            "model_used": self._model,
            "error": reason,
        }

    async def close(self) -> None:
        await self._http.aclose()
