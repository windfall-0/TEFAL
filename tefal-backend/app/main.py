"""tefal-backend 진입점.

실행: uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
"""

import asyncio
import contextlib
from contextlib import asynccontextmanager

import httpx
from fastapi import APIRouter, Depends, FastAPI

from app.ai.analysis import AiService
from app.ai.gemini import GeminiClient
from app.config import Settings
from app.core.auth import require_token
from app.core.cache import SqliteCache
from app.core.errors import install_error_handlers
from app.core.logging import setup_logging
from app.core.metrics import install_metrics_middleware
from app.hubble.client import HubbleClient
from app.incidents.collector import Collector, LokiClient
from app.incidents.detections import DetectionCollector
from app.incidents.levels import SigmaLevels
from app.incidents.store import IncidentStore
from app.incidents.tempo import TempoClient
from app.k8s import K8sClient
from app.routers import ai, incidents, infra, ingest, ops, policies, ti
from app.ti.geo import GeoIP
from app.ti.service import TiService


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    app.state.cache = await SqliteCache.open(settings.cache_db_path)
    app.state.http = httpx.AsyncClient(timeout=settings.http_timeout_seconds)
    app.state.incidents = await IncidentStore.open(settings.cache_db_path)
    app.state.incidents_lock = asyncio.Lock()
    app.state.sigma_levels = SigmaLevels(settings.sigma_levels_file)
    app.state.pod_count_cache = {}
    app.state.infra_cache = {}
    app.state.k8s = K8sClient.in_cluster(settings.k8s_api_url) if settings.k8s_enabled else None
    app.state.hubble = (
        HubbleClient(settings.hubble_relay_addr, settings.hubble_timeout_sec) if settings.hubble_enabled else None
    )
    app.state.tempo = (
        TempoClient(app.state.http, settings.tempo_url, settings.tempo_otlp_url)
        if settings.tempo_export_enabled
        else None
    )
    app.state.geo = GeoIP(settings.geoip_city_db, settings.geoip_asn_db)
    app.state.ti = TiService(settings, app.state.cache, app.state.http, app.state.geo)
    loki = LokiClient(app.state.http, settings.loki_url)
    gemini = (
        GeminiClient(app.state.http, settings.gemini_api_key.get_secret_value(), settings.gemini_model)
        if settings.gemini_api_key and settings.gemini_model
        else None
    )
    app.state.ai = AiService(settings, app.state.cache, app.state.incidents, loki, gemini, app.state.ti)
    task = None
    if settings.collector_enabled:
        collector = Collector(
            settings,
            app.state.incidents,
            loki,
            app.state.sigma_levels,
            app.state.incidents_lock,
            app.state.tempo,
            DetectionCollector(settings, app.state.incidents, loki),
        )
        task = asyncio.create_task(collector.run(), name="tetragon-collector")
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        app.state.geo.close()
        await app.state.http.aclose()
        if app.state.k8s is not None:
            await app.state.k8s.close()
        if app.state.hubble is not None:
            await app.state.hubble.close()
        await app.state.incidents.close()
        await app.state.cache.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    setup_logging(settings.secret_values())

    app = FastAPI(title="tefal-backend", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings

    install_error_handlers(app)
    install_metrics_middleware(app)

    app.include_router(ops.router)
    app.include_router(ingest.router)  # Falcosidekick 전용 토큰으로 따로 인증

    # Grafana 토큰(TEFAL_API_TOKEN)이 필요한 API 라우터
    for router in _api_routers():
        app.include_router(router, dependencies=AUTH)
    return app


AUTH = [Depends(require_token)]


def _api_routers() -> list[APIRouter]:
    return [incidents.router, infra.router, policies.router, ti.router, ai.router]
