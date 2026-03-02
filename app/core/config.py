"""
core/config.py

Centralises all environment-based configuration for ATLAS.

Added log file paths for the prototype phase (Loghub dataset parsing).
In production these settings are irrelevant once Elasticsearch is the data source.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Application
    app_name: str  = "ATLAS"
    app_env:  str  = "development"
    debug:    bool = True

    # Elasticsearch
    elastic_host:            str = "http://localhost:9201"
    elastic_username:        str = "elastic"
    elastic_password:        str = "changeme"
    elastic_index_logs:      str = "atlas-logs-*"
    elastic_index_incidents: str = "atlas-incidents"

    # Redis
    redis_host:     str = "localhost"
    redis_port:     int = 6379
    redis_db:       int = 0
    redis_password: str = ""

    # Ollama LLM
    ollama_base_url: str = "http://localhost:11434"
    ollama_model:    str = "llama3"

    # Wazuh
    wazuh_api_url:  str = "https://localhost:55000"
    wazuh_username: str = "wazuh"
    wazuh_password: str = "wazuh_password"

    # Risk Thresholds
    risk_warn_threshold:       int   = 1
    risk_soft_limit_threshold: int   = 3
    risk_hard_block_threshold: int   = 5
    anomaly_score_threshold:   float = -0.1

    # Anomaly Detection
    isolation_forest_contamination: float = 0.05
    isolation_forest_n_estimators:  int   = 100
    baseline_window_minutes:        int   = 15

    # ── Prototype: Local Loghub log-file paths ───────────────────────────────
    # These are only used during the prototyping phase while Elasticsearch is
    # not yet available.  In production, remove these and use the ES queries.
    #
    # Expected Loghub dataset layout (place files under data/logs/):
    #   data/logs/apache/Apache_2k.log          — Apache Combined Log Format
    #   data/logs/linux/Linux_2k.log            — Linux syslog
    #   data/logs/windows/Windows_2k.log        — Windows Event Log (text/CSV)
    log_dir:                str = "data/logs"
    apache_log_file:        str = "data/logs/apache/Apache_2k.log"
    linux_syslog_file:      str = "data/logs/linux/Linux_2k.log"
    windows_event_log_file: str = "data/logs/windows/Windows_2k.log"
    # Maximum lines read per call — keeps memory bounded during prototyping
    log_parse_max_lines:    int = 5000

    class Config:
        env_file       = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached singleton of Settings.
    lru_cache ensures we parse .env only once per process.
    """
    return Settings()
