"""운영 엔드포인트 (5.6). 인증 없음 — 클러스터 내부에서만 접근."""

import asyncio

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(tags=["ops"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


async def _check_http(client: httpx.AsyncClient, url: str) -> str:
    try:
        r = await client.get(url)
        return "ok" if r.status_code == 200 else f"http {r.status_code}"
    except httpx.HTTPError as e:
        return f"error: {type(e).__name__}"


async def _check_cache(request: Request) -> str:
    try:
        await request.app.state.cache.ping()
        return "ok"
    except Exception as e:  # noqa: BLE001 - readiness는 어떤 실패든 not ready
        return f"error: {type(e).__name__}"


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    http: httpx.AsyncClient = request.app.state.http
    tempo, loki, cache = await asyncio.gather(
        _check_http(http, f"{settings.tempo_url.rstrip('/')}/ready"),
        _check_http(http, f"{settings.loki_url.rstrip('/')}/ready"),
        _check_cache(request),
    )
    checks = {"tempo": tempo, "loki": loki, "cache": cache}
    ready = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", **checks},
        status_code=200 if ready else 503,
    )


@router.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
