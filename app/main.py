"""
main.py — ATLAS FastAPI Application

BUG FIX APPLIED:
- [FIX #3] DataCollectionMiddleware is now registered BEFORE lifespan runs
  (correct Starlette ordering). Clients are set on app.state inside lifespan,
  and the middleware reads them lazily via request.app.state on each request.
  The previous approach called add_data_collection_middleware() at module-load
  time when elastic_client / redis_client were still None, so the middleware
  was never actually added.

New routers registered:
- routes_network   → GET /api/metrics/network
- routes_endpoints → GET /api/metrics/endpoints
- routes_incidents.router_proto → GET /api/incidents/recent
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import routes_dashboard, routes_settings
from app.api.routes_incidents import (
    init_dependencies as incidents_init,
    router_v1         as incidents_router_v1,
    router_proto      as incidents_router_proto,
)
from app.api import routes_network, routes_endpoints
from app.core.config import get_settings
from app.integrations.elastic_client import ElasticClient
from app.integrations.redis_client import RedisClient
from app.integrations.llm_copilot import AICopilotAnalyst
from app.integrations.wazuh_client import WazuhClient
from app.ml.anomaly_engine import AnomalyDetector
from app.services.incident_service import IncidentService
from app.services.risk_manager import ProgressiveContainmentManager
from app.middleware.logging import DataCollectionMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()

# ─── Global Singletons ────────────────────────────────────────────────────────

elastic_client:   ElasticClient                = None
redis_client:     RedisClient                  = None
wazuh_client:     WazuhClient                  = None
copilot:          AICopilotAnalyst              = None
anomaly_detector: AnomalyDetector               = None
risk_manager:     ProgressiveContainmentManager = None


# ─── Application Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialises all service clients on startup and tears them down on shutdown.

    FIX #3 — Clients are assigned to app.state here (after init) so the
    already-registered DataCollectionMiddleware can access them lazily via
    request.app.state on every request.
    """
    global elastic_client, redis_client, wazuh_client, copilot, anomaly_detector, risk_manager

    logger.info(f"Starting {settings.app_name} backend  [env: {settings.app_env}]")

    # ── Elasticsearch ──
    elastic_client = ElasticClient()
    es_ok = await elastic_client.ping()
    if es_ok:
        logger.info("Elasticsearch connection established.")
    else:
        logger.warning(
            "Elasticsearch unreachable at startup. Dashboard queries will fail "
            "until ES is available. Prototype log-file endpoints will still work."
        )

    # ── Redis ──
    redis_client = RedisClient()
    await redis_client.connect()
    if await redis_client.is_connected():
        logger.info("Redis connection established.")
    else:
        logger.warning("Redis unavailable. Real-time metrics will be limited.")

    # ── Wazuh + LLM ──
    wazuh_client = WazuhClient()
    copilot      = AICopilotAnalyst()

    # ── ML engine ──
    anomaly_detector = AnomalyDetector()
    if anomaly_detector.is_trained:
        logger.info(f"Anomaly model loaded. Trained at: {anomaly_detector._trained_at}")
    else:
        logger.warning(
            "No anomaly model trained yet. Call POST /api/v1/dashboard/anomaly-model/train "
            "after ingesting historical logs."
        )

    # ── Services ──
    risk_manager = ProgressiveContainmentManager(
        redis_client=redis_client,
        wazuh_client=wazuh_client,
    )

    # ── Inject dependencies into ES-backed routers ──
    routes_dashboard.init_dependencies(elastic_client, redis_client, anomaly_detector)
    incidents_init(elastic_client, copilot, risk_manager)

    # ── FIX #3: Expose initialised clients on app.state ──────────────────────
    # The DataCollectionMiddleware (registered below at build time) reads these
    # lazily on every request via request.app.state.  They must be set here,
    # after init, NOT at module load time (when they are still None).
    app.state.elastic_client = elastic_client
    app.state.redis_client   = redis_client

    logger.info(f"{settings.app_name} startup complete.")

    yield  # ── Application runs ──

    # ── Shutdown ──
    logger.info(f"Shutting down {settings.app_name}...")
    await elastic_client.close()
    if redis_client:
        await redis_client.close()
    await wazuh_client.close()
    await copilot.close()
    logger.info("All connections closed. Shutdown complete.")


# ─── FastAPI Application ──────────────────────────────────────────────────────

app = FastAPI(
    title="ATLAS — Advanced Traffic Layer Anomaly System",
    description=(
        "Cloud-native SOC dashboard backend with ML-powered anomaly detection, "
        "progressive risk containment, and AI-assisted incident investigation.\n\n"
        "**Prototype endpoints** (log-file backed):\n"
        "- `GET /api/metrics/network` — Apache log aggregation\n"
        "- `GET /api/metrics/endpoints` — Syslog + Windows event aggregation\n"
        "- `GET /api/incidents/recent` — Combined critical incident feed for LLM\n"
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["https://your-soc-frontend.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Data Collection Middleware ─────────────────────────────────────────────────
# FIX #3 — Register the middleware HERE at app-build time (before lifespan),
# which is the only valid Starlette registration window.  Clients are NOT passed
# as constructor arguments; the middleware reads them lazily from app.state on
# each request (set during lifespan above).
app.add_middleware(DataCollectionMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
# ES-backed (production) routers
app.include_router(routes_dashboard.router)
app.include_router(incidents_router_v1)
app.include_router(routes_settings.router)

# Prototype routers (Loghub log-file backed)
app.include_router(routes_network.router)
app.include_router(routes_endpoints.router)
app.include_router(incidents_router_proto)


# ── Global Exception Handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error":  "Internal server error",
            "detail": str(exc) if settings.debug else "Contact your SOC administrator.",
        },
    )


# ── Root / Health ─────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "service":     settings.app_name,
        "version":     "1.1.0",
        "status":      "operational",
        "environment": settings.app_env,
        "docs":        "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    """Lightweight health probe for container orchestration."""
    es_healthy = await elastic_client.ping() if elastic_client else False
    return {
        "status":          "healthy",
        "elasticsearch":   "connected"  if es_healthy else "disconnected",
        "anomaly_model":   "trained"    if (anomaly_detector and anomaly_detector.is_trained) else "untrained",
        "prototype_mode":  True,   # log-file endpoints active
    }
