"""Falcosidekick webhook 수신 (5.1 POST /ingest/falco). Grafana용 토큰과 다른 토큰을 쓴다."""

import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.errors import ApiError
from app.incidents.falco import ingest_falco

router = APIRouter(tags=["ingest"])


def _check_token(request: Request) -> None:
    expected = request.app.state.settings.falco_webhook_token
    if expected is None or not expected.get_secret_value():
        raise ApiError(503, "falco_webhook_disabled", "FALCO_WEBHOOK_TOKEN이 설정되지 않았습니다")
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(
        token.strip().encode(), expected.get_secret_value().encode()
    ):
        raise ApiError(401, "unauthorized", "토큰이 올바르지 않습니다")


@router.post("/ingest/falco", status_code=202)
async def falco_webhook(request: Request) -> JSONResponse:
    _check_token(request)
    try:
        body = await request.json()
    except ValueError:
        raise ApiError(400, "invalid_request", "JSON 본문이 필요합니다") from None
    if not isinstance(body, dict):
        raise ApiError(400, "invalid_request", "JSON 객체가 필요합니다")
    app = request.app
    async with app.state.incidents_lock:
        result = await ingest_falco(
            app.state.incidents, app.state.sigma_levels, app.state.settings, body, app.state.tempo
        )
    return JSONResponse(result, status_code=202)
