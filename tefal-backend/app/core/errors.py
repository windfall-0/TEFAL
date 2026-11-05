"""오류 응답 규약: 4xx/5xx + {"error": "...", "detail": "..."} (3.4)."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status_code: int, error: str, detail: str = "") -> None:
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.detail = detail


def error_body(error: str, detail: str = "") -> dict:
    return {"error": error, "detail": detail}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(error_body(exc.error, exc.detail), status_code=exc.status_code)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        error = {401: "unauthorized", 404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error"
        )
        return JSONResponse(
            error_body(error, str(exc.detail or "")),
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        parts = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e.get("loc", []) if x not in ("query", "path"))
            parts.append(f"{loc}: {e.get('msg')}")
        return JSONResponse(error_body("invalid_request", "; ".join(parts)), status_code=400)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return JSONResponse(error_body("internal_error", type(exc).__name__), status_code=500)
