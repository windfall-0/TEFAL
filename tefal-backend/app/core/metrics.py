"""Prometheus 메트릭 (5.6)."""

import time

from fastapi import FastAPI, Request
from prometheus_client import Counter, Histogram

REQUESTS = Counter(
    "tefal_http_requests_total", "HTTP 요청 수", ["method", "route", "status"]
)
REQUEST_LATENCY = Histogram(
    "tefal_http_request_duration_seconds", "HTTP 요청 지연", ["method", "route"]
)
EXTERNAL_CALLS = Counter(
    "tefal_external_calls_total", "외부 API 호출 수", ["service", "outcome"]
)  # outcome: ok | error | skipped_limit
CACHE_LOOKUPS = Counter(
    "tefal_cache_lookups_total", "캐시 조회", ["namespace", "result"]
)  # result: hit | miss | stale
AI_GENERATION_SECONDS = Histogram(
    "tefal_ai_generation_seconds", "AI 해석 생성 시간", buckets=(1, 2, 5, 10, 20, 30, 60)
)


def install_metrics_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def _metrics(request: Request, call_next):
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            # 경로 템플릿으로 기록해 trace_id/ip별로 라벨이 늘어나지 않게 한다
            path = getattr(route, "path", "unmatched")
            REQUESTS.labels(request.method, path, str(status)).inc()
            REQUEST_LATENCY.labels(request.method, path).observe(time.perf_counter() - start)
