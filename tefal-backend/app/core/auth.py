"""Bearer 토큰 인증 (3.3). /healthz, /metrics, /readyz는 이 의존성을 쓰지 않는다."""

import secrets

from fastapi import Request

from app.core.errors import ApiError


async def require_token(request: Request) -> None:
    expected = request.app.state.settings.tefal_api_token.get_secret_value()
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ApiError(401, "unauthorized", "Bearer 토큰이 필요합니다")
    if not secrets.compare_digest(token.strip().encode(), expected.encode()):
        raise ApiError(401, "unauthorized", "토큰이 올바르지 않습니다")
