"""
main.py — ATLAS FastAPI Application

Wires together all components at startup:
- Initializes singleton service clients (ES, Wazuh, Ollama, ML model)
- Injects dependencies into API routers
- Registers startup/shutdown lifecycle hooks for clean resource management

Singleton pattern for service clients is intentional:
- Elasticsearch and httpx clients maintain connection pools — recreating them
  per-request is expensive and would exhaust file descriptors under load
- The ML model (IsolationForest) is loaded from disk once and kept in memory
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import routes_dashboard, routes_incidents, routes_settings
from app.api.routes_auth import router as auth_router
from app.core.config import get_settings
from app.db.database import init_db
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
# These are initialized once at startup and shared across all requests.

elastic_client: ElasticClient = None
redis_client: RedisClient = None
wazuh_client: WazuhClient = None
copilot: AICopilotAnalyst = None
anomaly_detector: AnomalyDetector = None
risk_manager: ProgressiveContainmentManager = None


# ─── Application Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async context manager for application startup and shutdown.
    Preferred over deprecated @app.on_event handlers in FastAPI 0.95+.
    """
    global elastic_client, redis_client, wazuh_client, copilot, anomaly_detector, risk_manager

    logger.info(f"Starting {settings.app_name} backend...")

    # ── Initialize PostgreSQL (create tables if not exists) ──
    try:
        await init_db()
        logger.info("PostgreSQL database initialized.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}. Auth endpoints will be unavailable.")

    # ── Initialize integrations ──
    elastic_client = ElasticClient()
    es_ok = await elastic_client.ping()
    if not es_ok:
        logger.warning(
            "Elasticsearch unreachable at startup. Dashboard queries will fail until ES is available."
        )
    else:
        logger.info("Elasticsearch connection established.")

    redis_client = RedisClient()
    await redis_client.connect()
    if await redis_client.is_connected():
        logger.info("Redis connection established.")
    else:
        logger.warning("Redis unavailable. Real-time metrics will be limited.")

    wazuh_client = WazuhClient()
    copilot = AICopilotAnalyst()

    # ── Initialize ML engine ──
    anomaly_detector = AnomalyDetector()
    if anomaly_detector.is_trained:
        logger.info(f"Anomaly model loaded. Trained at: {anomaly_detector._trained_at}")
    else:
        logger.warning(
            "No anomaly model trained yet. Call POST /api/v1/dashboard/anomaly-model/train "
            "after ingesting historical logs."
        )

    # ── Initialize services ──
    risk_manager = ProgressiveContainmentManager(
        redis_client=redis_client,
        wazuh_client=wazuh_client,
    )

    # ── Inject dependencies into routers ──
    routes_dashboard.init_dependencies(elastic_client, redis_client, anomaly_detector)
    routes_incidents.init_dependencies(elastic_client, copilot, risk_manager)

    # ── Store clients in app.state for middleware lazy access ──
    # DataCollectionMiddleware reads from app.state at request time,
    # so it always gets the initialized clients regardless of startup order.
    app.state.elastic_client = elastic_client
    app.state.redis_client = redis_client

    logger.info(f"{settings.app_name} startup complete. ENV: {settings.app_env}")

    yield  # ── Application runs ──

    # ── Shutdown: gracefully close connection pools ──
    logger.info(f"Shutting down {settings.app_name}...")
    await elastic_client.close()
    if redis_client:
        await redis_client.close()
    await wazuh_client.close()
    await copilot.close()
    logger.info("All connections closed. Shutdown complete.")


# ─── FastAPI Application ───────────────────────────────────────────────────────

app = FastAPI(
    title="ATLAS — Advanced Traffic Layer Anomaly System",
    description=(
        "Cloud-native SOC dashboard backend with ML-powered anomaly detection, "
        "progressive risk containment, and AI-assisted incident investigation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# In production, replace ["*"] with the explicit frontend domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["https://your-soc-frontend.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Data Collection Middleware ─────────────────────────────────────────────────────
# Registered unconditionally here. The middleware reads elastic/redis clients from
# app.state at request time (populated during lifespan startup), so it's safe to
# register before lifespan runs. This avoids the race condition where clients are
# None at module load time.
app.add_middleware(DataCollectionMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(routes_dashboard.router)
app.include_router(routes_incidents.router)
app.include_router(routes_settings.router)


# ── Global Exception Handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    """
    Catches unhandled exceptions and returns a consistent JSON error response.
    Prevents stack traces from leaking to the frontend in production.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.debug else "Contact your SOC administrator.",
        },
    )


# ── Root / Health ─────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "service": settings.app_name,
        "version": "1.0.0",
        "status": "operational",
        "environment": settings.app_env,
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    """
    Lightweight health probe for container orchestration (K8s liveness check).
    Returns 200 as long as the FastAPI process is alive.
    ES / Redis connectivity is checked separately (readiness probe pattern).
    """
    es_healthy = await elastic_client.ping() if elastic_client else False
    return {
        "status": "healthy",
        "elasticsearch": "connected" if es_healthy else "disconnected",
        "anomaly_model": "trained" if (anomaly_detector and anomaly_detector.is_trained) else "untrained",
    }
