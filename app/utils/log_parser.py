"""
utils/log_parser.py

Prototype-phase log parsing utility for ATLAS.

Reads and parses raw Loghub dataset files (Apache, Linux Syslog, Windows
Event Logs) into structured Python dicts that the API routers can aggregate
and serve to the frontend.

Every public function is clearly marked with a TODO block that explains how
to replace the local file I/O with the equivalent Elasticsearch query when
the system moves to production.

Supported Loghub formats
─────────────────────────
Apache Combined Log Format
  <ip> - <user> [<timestamp>] "<method> <path> <proto>" <status> <bytes> "<ref>" "<ua>"
  e.g. 64.242.88.10 - - [07/Mar/2004:16:05:49 -0800] "GET /twiki/bin/edit/Main HTTP/1.1" 401 12846

Linux Syslog (RFC 3164-ish)
  <Month> <day> <HH:MM:SS> <hostname> <process>[<pid>]: <message>
  e.g. Jun 14 15:16:01 combo sshd[19939]: Failed password for illegal user rootkit from 81.0.0.1

Windows Event Log (Loghub plain-text variant)
  <date> <time> <type> <category> <event_id> <source> <message>
  e.g. 2004-10-28 10:30:00 Error (0) 529 Security Logon Failure: ...
"""

import re
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# ─── Compiled regexes ─────────────────────────────────────────────────────────

# Apache Combined Log Format
_APACHE_RE = re.compile(
    r'(?P<ip>\S+)'                              # source IP
    r'\s+\S+\s+\S+\s+'                         # ident, auth (usually -)
    r'\[(?P<timestamp>[^\]]+)\]\s+'             # [timestamp]
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+'  # "METHOD /path HTTP/x.x"
    r'(?P<status>\d{3})\s+'                    # status code
    r'(?P<bytes>\S+)'                           # bytes sent ("-" means 0)
)

# Linux Syslog
_SYSLOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)'
)

# Patterns within syslog messages that indicate auth failures
_SSH_FAIL_RE   = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)', re.I)
_AUTH_FAIL_RE  = re.compile(r'authentication failure.*user=(?P<user>\S+)', re.I)
_INVALID_USER  = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)', re.I)
_SUDO_FAIL_RE  = re.compile(r'sudo.*authentication failure', re.I)

# Windows Event Log (plain-text Loghub variant)
# Format: date  time  type  category  eventid  source  message...
_WIN_EVT_RE = re.compile(
    r'(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<type>\w+)\s+'
    r'\((?P<category>[^)]*)\)\s+'
    r'(?P<event_id>\d+)\s+'
    r'(?P<source>\S+)\s+'
    r'(?P<message>.+)'
)

# Windows login-failure event IDs (528/529 = W2K, 4625 = Vista+)
_WIN_LOGIN_FAIL_IDS = {"529", "4625", "680"}

# ─── Apache log parser ────────────────────────────────────────────────────────

# TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
# e.g., response = elastic_client.search(index="atlas-network-logs",
#         body={"size": 5000, "sort": [{"@timestamp": {"order": "desc"}}],
#               "query": {"range": {"@timestamp": {"gte": "now-24h"}}}})
def fetch_recent_network_logs(
    hours: int = 24,
    max_lines: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Parse the Apache access log file and return a list of structured request
    records for the last `hours` hours (best-effort — Loghub files lack a
    real year so we return all records when the timestamp cannot be filtered).

    Each record:
        {
            "ip": str,
            "timestamp_raw": str,      # original log timestamp string
            "timestamp": datetime | None,
            "method": str,
            "path": str,
            "status": int,
            "bytes": int,
        }

    TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    e.g., response = elastic_client.search(index="atlas-network-logs", ...)
    """
    max_lines = max_lines or settings.log_parse_max_lines
    log_path  = Path(settings.apache_log_file)

    if not log_path.exists():
        logger.warning(f"Apache log not found at {log_path}. Returning empty list.")
        return []

    records: List[Dict[str, Any]] = []
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh):
                if line_no >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue

                m = _APACHE_RE.match(line)
                if not m:
                    continue

                ts_raw = m.group("timestamp")
                ts     = _parse_apache_timestamp(ts_raw)

                # If we could parse the timestamp, apply the time filter
                if ts and ts < cutoff:
                    continue

                records.append({
                    "ip":            m.group("ip"),
                    "timestamp_raw": ts_raw,
                    "timestamp":     ts,
                    "method":        m.group("method"),
                    "path":          m.group("path"),
                    "status":        int(m.group("status")),
                    "bytes":         int(m.group("bytes")) if m.group("bytes") != "-" else 0,
                    "raw_line":      line,
                })
    except OSError as exc:
        logger.error(f"Failed to read Apache log {log_path}: {exc}")

    logger.info(f"[log_parser] Parsed {len(records)} Apache records from {log_path}")
    return records


# ─── Syslog parser ────────────────────────────────────────────────────────────

# TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
# e.g., response = elastic_client.search(index="atlas-syslog-*",
#         body={"query": {"bool": {"must": [
#             {"match": {"message": "Failed password"}},
#             {"range": {"@timestamp": {"gte": "now-24h"}}}]}}})
def fetch_recent_syslog_events(
    hours: int = 24,
    max_lines: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Parse the Linux syslog file and return structured event records.

    Each record:
        {
            "timestamp_raw": str,
            "timestamp": datetime | None,
            "hostname": str,
            "process": str,
            "pid": str | None,
            "message": str,
            "event_type": str,      # "ssh_fail" | "auth_fail" | "sudo_fail" | "general"
            "source_ip": str | None,
            "username": str | None,
            "severity": str,        # "Low" | "Medium" | "High" | "Critical"
        }

    TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    e.g., response = elastic_client.search(index="atlas-syslog-*", ...)
    """
    max_lines = max_lines or settings.log_parse_max_lines
    log_path  = Path(settings.linux_syslog_file)

    if not log_path.exists():
        logger.warning(f"Syslog not found at {log_path}. Returning empty list.")
        return []

    records: List[Dict[str, Any]] = []
    cutoff  = datetime.utcnow() - timedelta(hours=hours)

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh):
                if line_no >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue

                m = _SYSLOG_RE.match(line)
                if not m:
                    continue

                ts_raw = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                ts     = _parse_syslog_timestamp(ts_raw)

                if ts and ts < cutoff:
                    continue

                message    = m.group("message")
                event_type, src_ip, username, severity = _classify_syslog(message)

                records.append({
                    "timestamp_raw": ts_raw,
                    "timestamp":     ts,
                    "hostname":      m.group("hostname"),
                    "process":       m.group("process").strip(),
                    "pid":           m.group("pid"),
                    "message":       message,
                    "event_type":    event_type,
                    "source_ip":     src_ip,
                    "username":      username,
                    "severity":      severity,
                    "raw_line":      line,
                })
    except OSError as exc:
        logger.error(f"Failed to read syslog {log_path}: {exc}")

    logger.info(f"[log_parser] Parsed {len(records)} syslog records from {log_path}")
    return records


# ─── Windows Event Log parser ─────────────────────────────────────────────────

# TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
# e.g., response = elastic_client.search(index="atlas-winevent-*",
#         body={"query": {"bool": {"must": [
#             {"terms": {"event_id": [4625, 529]}},
#             {"range": {"@timestamp": {"gte": "now-24h"}}}]}}})
def fetch_recent_windows_events(
    hours: int = 24,
    max_lines: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Parse the Windows Event Log Loghub file and return structured event records.

    Each record:
        {
            "timestamp_raw": str,
            "timestamp": datetime | None,
            "event_type": str,       # "Error" | "Warning" | "Information"
            "event_id": str,
            "source": str,
            "message": str,
            "is_login_failure": bool,
            "severity": str,
            "username": str | None,
        }

    TODO [PRODUCTION]: Replace local file parsing with Elasticsearch query.
    e.g., response = elastic_client.search(index="atlas-winevent-*", ...)
    """
    max_lines = max_lines or settings.log_parse_max_lines
    log_path  = Path(settings.windows_event_log_file)

    if not log_path.exists():
        logger.warning(f"Windows event log not found at {log_path}. Returning empty list.")
        return []

    records: List[Dict[str, Any]] = []
    cutoff  = datetime.utcnow() - timedelta(hours=hours)

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh):
                if line_no >= max_lines:
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                m = _WIN_EVT_RE.match(line)
                if not m:
                    continue

                ts_raw = f"{m.group('date')} {m.group('time')}"
                ts     = _parse_windows_timestamp(ts_raw)

                if ts and ts < cutoff:
                    continue

                event_id        = m.group("event_id")
                evt_type        = m.group("type")
                message         = m.group("message")
                is_login_fail   = event_id in _WIN_LOGIN_FAIL_IDS
                severity        = _classify_windows_event(evt_type, event_id)
                username        = _extract_win_username(message)

                records.append({
                    "timestamp_raw":   ts_raw,
                    "timestamp":       ts,
                    "event_type":      evt_type,
                    "event_id":        event_id,
                    "source":          m.group("source"),
                    "message":         message,
                    "is_login_failure": is_login_fail,
                    "severity":        severity,
                    "username":        username,
                    "raw_line":        line,
                })
    except OSError as exc:
        logger.error(f"Failed to read Windows event log {log_path}: {exc}")

    logger.info(f"[log_parser] Parsed {len(records)} Windows event records from {log_path}")
    return records


# ─── Aggregate helpers (used by routers) ──────────────────────────────────────

def aggregate_network_metrics(
    records: List[Dict[str, Any]],
    top_n: int = 5,
    excessive_request_threshold: int = 100,
) -> Dict[str, Any]:
    """
    Aggregate raw Apache records into the shape expected by the network router.

    Returns:
        {
            "nodes":           List[dict],   # top_n IPs as network nodes
            "anomalies":       List[dict],   # IPs with suspicious behaviour
            "bandwidth_usage": dict,
            "summary":         dict,
        }
    """
    ip_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "request_count": 0,
        "bytes_sent":    0,
        "error_count":   0,
        "paths":         set(),
        "statuses":      defaultdict(int),
        "first_seen":    None,
        "last_seen":     None,
    })

    total_bytes   = 0
    total_errors  = 0
    hourly_bytes: Dict[str, int] = defaultdict(int)

    for rec in records:
        ip     = rec["ip"]
        stats  = ip_stats[ip]
        stats["request_count"] += 1
        stats["bytes_sent"]    += rec["bytes"]
        stats["statuses"][str(rec["status"])] += 1
        stats["paths"].add(rec["path"])
        total_bytes += rec["bytes"]

        if rec["status"] >= 400:
            stats["error_count"] += 1
            total_errors += 1

        # Track first/last seen
        ts = rec.get("timestamp")
        if ts:
            if stats["first_seen"] is None or ts < stats["first_seen"]:
                stats["first_seen"] = ts
            if stats["last_seen"]  is None or ts > stats["last_seen"]:
                stats["last_seen"]  = ts
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            hourly_bytes[hour_key] += rec["bytes"]

    # Sort IPs by request count and take top_n
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["request_count"], reverse=True)

    nodes = []
    for ip, s in sorted_ips[:top_n]:
        status = "normal"
        if s["request_count"] >= excessive_request_threshold:
            status = "blocked"
        elif s["error_count"] > s["request_count"] * 0.3:
            status = "warning"

        nodes.append({
            "id":            f"node-{ip}",
            "ip":            ip,
            "request_count": s["request_count"],
            "bytes_sent":    s["bytes_sent"],
            "status":        status,
            "top_paths":     list(s["paths"])[:5],
        })

    # Build anomaly list
    anomalies = []
    for ip, s in ip_stats.items():
        flags: List[str] = []
        severity = "Low"

        if s["request_count"] >= excessive_request_threshold:
            flags.append("excessive_requests")
            severity = "High"
        if s["statuses"].get("500", 0) + s["statuses"].get("502", 0) > 3:
            flags.append("server_error")
            severity = max(severity, "Medium", key=lambda x: ["Low","Medium","High","Critical"].index(x))
        error_rate = s["error_count"] / max(s["request_count"], 1)
        if error_rate > 0.4:
            flags.append("high_error_rate")
            severity = "Critical" if error_rate > 0.7 else "High"

        if flags:
            anomalies.append({
                "id":            f"anom-{ip}",
                "source_ip":     ip,
                "anomaly_type":  ", ".join(flags),
                "request_count": s["request_count"],
                "error_count":   s["error_count"],
                "severity":      severity,
                "first_seen":    s["first_seen"].isoformat() if s["first_seen"] else "unknown",
                "last_seen":     s["last_seen"].isoformat()  if s["last_seen"]  else "unknown",
                "sample_paths":  list(s["paths"])[:3],
            })

    # Sort anomalies by severity
    sev_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    anomalies.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

    bandwidth_chart = [
        {"hour": h, "bytes": b} for h, b in sorted(hourly_bytes.items())
    ]

    total_req = len(records)
    return {
        "nodes":     nodes,
        "anomalies": anomalies,
        "bandwidth_usage": {
            "total_bytes_mb":  round(total_bytes / (1024 * 1024), 2),
            "total_bytes":     total_bytes,
            "hourly_chart":    bandwidth_chart,
        },
        "summary": {
            "total_requests": total_req,
            "unique_ips":     len(ip_stats),
            "total_errors":   total_errors,
            "error_rate":     round(total_errors / max(total_req, 1), 4),
        },
    }


def aggregate_endpoint_alerts(
    syslog_records: List[Dict[str, Any]],
    windows_records: List[Dict[str, Any]],
    top_n: int = 50,
) -> Dict[str, Any]:
    """
    Combine syslog and Windows Event Log records into a unified endpoint alert list.

    Returns:
        {
            "alerts":           List[dict],
            "summary":          dict,
            "auth_failure_ips": List[dict],
        }
    """
    alerts: List[Dict[str, Any]] = []
    auth_fail_ips: Dict[str, int] = defaultdict(int)

    # ── Syslog → alerts ──
    for idx, rec in enumerate(syslog_records):
        if rec["event_type"] == "general":
            continue   # skip routine syslog chatter

        if rec.get("source_ip"):
            auth_fail_ips[rec["source_ip"]] += 1

        ts_str = (
            rec["timestamp"].isoformat()
            if rec.get("timestamp") else rec.get("timestamp_raw", "unknown")
        )

        alerts.append({
            "id":             f"sys-{idx}",
            "workstation_id": rec.get("hostname", "linux-host"),
            "alert_type":     rec["event_type"],
            "source_ip":      rec.get("source_ip"),
            "username":       rec.get("username"),
            "message":        rec["message"][:200],
            "severity":       rec["severity"],
            "timestamp":      ts_str,
            "raw_line":       rec.get("raw_line", ""),
        })

    # ── Windows events → alerts ──
    for idx, rec in enumerate(windows_records):
        if not rec["is_login_failure"] and rec["event_type"] not in ("Error",):
            continue

        ts_str = (
            rec["timestamp"].isoformat()
            if rec.get("timestamp") else rec.get("timestamp_raw", "unknown")
        )

        alerts.append({
            "id":             f"win-{idx}",
            "workstation_id": f"WS-{rec['source'][:8]}",
            "alert_type":     "failed_login" if rec["is_login_failure"] else "system_error",
            "source_ip":      None,
            "username":       rec.get("username"),
            "message":        rec["message"][:200],
            "severity":       rec["severity"],
            "timestamp":      ts_str,
            "raw_line":       rec.get("raw_line", ""),
        })

    # Sort by severity then timestamp (most recent first)
    sev_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    alerts.sort(
        key=lambda x: (sev_order.get(x["severity"], 0), x["timestamp"]),
        reverse=True,
    )
    alerts = alerts[:top_n]

    # Top auth-failure IPs
    top_auth_fail = [
        {"ip": ip, "failure_count": cnt}
        for ip, cnt in sorted(auth_fail_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    critical_count = sum(1 for a in alerts if a["severity"] == "Critical")
    high_count     = sum(1 for a in alerts if a["severity"] == "High")
    hosts          = {a["workstation_id"] for a in alerts}

    return {
        "alerts": alerts,
        "summary": {
            "total_alerts":    len(alerts),
            "critical_count":  critical_count,
            "high_count":      high_count,
            "affected_hosts":  len(hosts),
        },
        "auth_failure_ips": top_auth_fail,
    }


def build_recent_incidents(
    network_anomalies: List[Dict[str, Any]],
    endpoint_alerts:   List[Dict[str, Any]],
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Merge the most severe anomalies from Apache and syslog/Windows parsers
    into a unified incident list suitable for LLM (Ollama) threat briefing.

    Returns top_n events sorted by severity.
    """
    sev_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    incidents: List[Dict[str, Any]] = []

    # ── Network anomalies → incidents ──
    for anom in network_anomalies:
        if sev_order.get(anom["severity"], 0) < 1:
            continue   # skip Low severity for incident feed
        incidents.append({
            "id":           f"inc-net-{anom['id']}",
            "source":       "apache",
            "event_type":   anom["anomaly_type"],
            "source_ip":    anom["source_ip"],
            "username":     None,
            "severity":     anom["severity"],
            "timestamp":    anom["last_seen"],
            "description":  (
                f"IP {anom['source_ip']} made {anom['request_count']} requests "
                f"with {anom['error_count']} errors. "
                f"Flags: {anom['anomaly_type']}."
            ),
            "raw_evidence": anom["sample_paths"],
        })

    # ── Endpoint alerts → incidents ──
    for alert in endpoint_alerts:
        if sev_order.get(alert["severity"], 0) < 1:
            continue
        incidents.append({
            "id":           f"inc-ep-{alert['id']}",
            "source":       "syslog" if alert["id"].startswith("sys-") else "windows_event",
            "event_type":   alert["alert_type"],
            "source_ip":    alert.get("source_ip"),
            "username":     alert.get("username"),
            "severity":     alert["severity"],
            "timestamp":    alert["timestamp"],
            "description":  alert["message"],
            "raw_evidence": [alert.get("raw_line", "")] if alert.get("raw_line") else [],
        })

    # Sort and take top_n
    incidents.sort(
        key=lambda x: (sev_order.get(x["severity"], 0), x["timestamp"]),
        reverse=True,
    )
    return incidents[:top_n]


# ─── Private helpers ──────────────────────────────────────────────────────────

def _parse_apache_timestamp(ts_raw: str) -> Optional[datetime]:
    """
    Parse Apache Combined Log timestamp.
    e.g. "07/Mar/2004:16:05:49 -0800"
    """
    try:
        return datetime.strptime(ts_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def _parse_syslog_timestamp(ts_raw: str) -> Optional[datetime]:
    """
    Parse syslog timestamp (no year in RFC 3164 — assume current year).
    e.g. "Jun 14 15:16:01"
    """
    try:
        ts = datetime.strptime(ts_raw.strip(), "%b %d %H:%M:%S")
        return ts.replace(year=datetime.utcnow().year)
    except ValueError:
        return None


def _parse_windows_timestamp(ts_raw: str) -> Optional[datetime]:
    """Parse Windows event log timestamp. e.g. '2004-10-28 10:30:00'"""
    try:
        return datetime.strptime(ts_raw.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _classify_syslog(message: str) -> Tuple[str, Optional[str], Optional[str], str]:
    """
    Classify a syslog message and extract IoC fields.
    Returns (event_type, source_ip, username, severity).
    """
    m = _SSH_FAIL_RE.search(message)
    if m:
        return "ssh_brute_force", m.group("ip"), m.group("user"), "High"

    m = _INVALID_USER.search(message)
    if m:
        return "ssh_invalid_user", m.group("ip"), m.group("user"), "Medium"

    m = _AUTH_FAIL_RE.search(message)
    if m:
        return "auth_failure", None, m.group("user"), "Medium"

    if _SUDO_FAIL_RE.search(message):
        return "sudo_auth_failure", None, None, "High"

    if re.search(r"(panic|oops|kernel bug|out of memory|oom.?killer)", message, re.I):
        return "system_critical", None, None, "Critical"

    if re.search(r"(error|fail|denied|refused)", message, re.I):
        return "system_error", None, None, "Low"

    return "general", None, None, "Low"


def _classify_windows_event(event_type: str, event_id: str) -> str:
    """Map a Windows event type + ID to a severity string."""
    if event_id in _WIN_LOGIN_FAIL_IDS:
        return "High"
    if event_type == "Error":
        return "Medium"
    if event_type == "Warning":
        return "Low"
    return "Low"


def _extract_win_username(message: str) -> Optional[str]:
    """Try to extract a username from a Windows event log message."""
    m = re.search(r'(?:user(?:name)?|account)[:\s]+([^\s,;]+)', message, re.I)
    return m.group(1) if m else None
