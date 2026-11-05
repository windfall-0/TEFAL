"""공통 쿼리 파라미터 (3.2). Grafana 변수를 그대로 받는다."""

import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Query

from app.core.errors import ApiError
from app.core.validators import is_valid_k8s_name

DEFAULT_RANGE_MS = 60 * 60 * 1000  # from 생략 시 최근 1시간

ALLOWED_RUNTIMES = {"java", "php", "node"}
ALLOWED_STATUSES = {"blocked", "unblocked", "pending"}
ALLOWED_LEVELS = ("critical", "high", "medium", "low", "informational")  # 높은 순 (4.8)
_ALL_VALUES = {"", "all", "$__all", "*"}


@dataclass(frozen=True)
class CommonFilters:
    from_ms: int
    to_ms: int
    namespace: str | None  # None = 전체
    runtimes: frozenset[str] | None  # None = 전체, 소문자
    status: str | None  # None = 전체
    levels: frozenset[str] | None = None  # None = 전체


def _is_all(value: str | None) -> bool:
    return value is None or value.strip().lower() in _ALL_VALUES


def _split_multi(value: str) -> list[str]:
    # Grafana 다중 값: csv("java,php") / glob("{java,php}") 형식 모두 허용
    return [p.strip() for p in value.strip().strip("{}").split(",") if p.strip()]


def parse_time_range(from_ms: int | None, to_ms: int | None) -> tuple[int, int]:
    to_v = to_ms if to_ms is not None else int(time.time() * 1000)
    from_v = from_ms if from_ms is not None else to_v - DEFAULT_RANGE_MS
    if from_v < 0 or to_v < 0:
        raise ApiError(400, "invalid_time_range", "from/to는 epoch ms 양수여야 합니다")
    if from_v > to_v:
        raise ApiError(400, "invalid_time_range", "from이 to보다 큽니다")
    return from_v, to_v


def common_filters(
    from_: Annotated[int | None, Query(alias="from")] = None,
    to: int | None = None,
    namespace: str | None = None,
    runtime: str | None = None,
    status: str | None = None,
    level: str | None = None,
) -> CommonFilters:
    from_ms, to_ms = parse_time_range(from_, to)

    ns: str | None = None
    if not _is_all(namespace):
        ns = namespace.strip()
        if not is_valid_k8s_name(ns):
            raise ApiError(400, "invalid_namespace", "namespace 형식이 올바르지 않습니다")

    runtimes: frozenset[str] | None = None
    if not _is_all(runtime):
        values = {v.lower() for v in _split_multi(runtime)}
        if not values or values & _ALL_VALUES:
            values = set()
        bad = values - ALLOWED_RUNTIMES
        if bad:
            raise ApiError(400, "invalid_runtime", f"지원하지 않는 runtime: {','.join(sorted(bad))}")
        # 세 가지를 모두 고른 것(Grafana All의 csv 전개)은 전체와 같다 (runtime 미상 사건도 보이게)
        runtimes = frozenset(values) if values and values != ALLOWED_RUNTIMES else None

    st: str | None = None
    if not _is_all(status):
        st = status.strip().lower()
        if st not in ALLOWED_STATUSES:
            raise ApiError(400, "invalid_status", "status는 blocked | unblocked | pending | All")

    levels: frozenset[str] | None = None
    if not _is_all(level):
        values = {v.lower() for v in _split_multi(level)}
        if values & _ALL_VALUES:
            values = set()
        bad = values - set(ALLOWED_LEVELS)
        if bad:
            raise ApiError(400, "invalid_level", f"지원하지 않는 level: {','.join(sorted(bad))}")
        # 다섯 단계를 모두 고른 것(Grafana All의 csv 전개)은 전체와 같다
        levels = frozenset(values) if values and values != set(ALLOWED_LEVELS) else None

    return CommonFilters(from_ms, to_ms, ns, runtimes, st, levels)
