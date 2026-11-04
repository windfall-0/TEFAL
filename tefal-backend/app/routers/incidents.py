"""사건 API (5.1): ① 운영 현황, ② 사건 상세."""

import logging
import re
import time
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Query, Request

from app.core.errors import ApiError
from app.core.params import ALLOWED_LEVELS, CommonFilters, common_filters
from app.core.timefmt import fmt_hm, fmt_hms
from app.core.validators import is_valid_k8s_name, validate_trace_id
from app.incidents.store import Incident, IncidentStore

log = logging.getLogger(__name__)
router = APIRouter(tags=["incidents"])

STATUS_LABEL = {"blocked": "차단됨", "unblocked": "미차단", "pending": "판정 중"}
WINDOW_MS = 5 * 60 * 1000
_INTERVAL_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
MAX_BUCKETS = 2000

Filters = Annotated[CommonFilters, Depends(common_filters)]


def _store(request: Request) -> IncidentStore:
    return request.app.state.incidents


def _is_unblocked(status: str) -> bool:
    # 판정 중은 미차단 쪽에 넣어 센다 (4.4)
    return status != "blocked"


def to_model(inc: Incident, tz: str) -> dict:
    ms = inc.anchor_ms
    frac = f"{inc.start_ms % 1000:03d}"
    return {
        "trace_id": inc.trace_id,
        "start_ms": inc.start_ms,
        "anchor_ms": inc.anchor_ms,
        "time": fmt_hms(inc.start_ms, tz),
        "status": inc.status,
        "status_label": STATUS_LABEL[inc.status],
        "level": inc.level,
        "level_source": inc.level_source,
        "action": inc.action,
        "detected_by": inc.detected_by,
        "namespace": inc.namespace,
        "pod": inc.pod,
        "workload": f"{inc.namespace} / {inc.pod}",
        "node": inc.node,
        "runtime": inc.runtime,
        "runtime_detail": inc.runtime_detail or inc.runtime,
        "summary": inc.summary,
        "mitre": inc.mitre,
        "src_ip": inc.src_ip,
        "exec_id": inc.exec_id,
        "parent_exec_id": inc.parent_exec_id,
        "policy": inc.policy,
        "member_count": inc.member_count,
        "falco_rules": inc.falco_rules,
        "beyla_trace_id": inc.beyla_trace_id,
        "beyla_link_confidence": inc.beyla_link_confidence,
        "status_text": f"{STATUS_LABEL[inc.status]} · {inc.action}",
        "time_text": f"{fmt_hms(inc.start_ms, tz)}.{frac}",
        "mitre_text": " · ".join(inc.mitre) if inc.mitre else "-",
        "window_from_ms": inc.start_ms - WINDOW_MS,
        "window_to_ms": max(ms, inc.last_ms) + WINDOW_MS,
    }


@router.get("/incidents")
async def list_incidents(
    request: Request, f: Filters, limit: Annotated[int, Query(ge=1, le=1000)] = 100
) -> list[dict]:
    tz = request.app.state.settings.display_tz
    return [to_model(i, tz) for i in await _store(request).query(f, limit)]


async def _running_pods(request: Request, namespace: str | None) -> int | None:
    """Running pod 수 (kube-state-metrics). namespace 필터가 전체면 감시 대상 namespace 기준."""
    s = request.app.state.settings
    namespaces = [namespace] if namespace else s.watch_namespace_list
    if not namespaces:
        return None
    key = ",".join(sorted(namespaces))
    cache: dict = request.app.state.pod_count_cache
    hit = cache.get(key)
    if hit and time.monotonic() - hit[0] < 30:
        return hit[1]
    # namespace는 k8s 이름([a-z0-9-])만 통과시킨다. re.escape는 '-'를 '\-'로 바꿔 PromQL 문자열 오류가 난다
    namespaces = [n for n in namespaces if is_valid_k8s_name(n)]
    if not namespaces:
        return None
    sel = "|".join(namespaces)
    expr = f'count(kube_pod_status_phase{{phase="Running", namespace=~"{sel}"}} == 1) or vector(0)'
    try:
        r = await request.app.state.http.get(f"{s.prometheus_url.rstrip('/')}/api/v1/query", params={"query": expr})
        r.raise_for_status()
        result = r.json()["data"]["result"]
        value = int(float(result[0]["value"][1])) if result else 0
    except (httpx.HTTPError, KeyError, ValueError, IndexError) as e:
        log.warning("Prometheus 조회 실패: %s", type(e).__name__)
        return hit[1] if hit else None
    cache[key] = (time.monotonic(), value)
    return value


@router.get("/incidents/summary")
async def summary(request: Request, f: Filters) -> dict:
    tz = request.app.state.settings.display_tz
    items = await _store(request).query(f)
    unblocked = [i for i in items if _is_unblocked(i.status)]
    out = {
        "unblocked_count": len(unblocked),
        "unblocked_last_time": fmt_hm(max(i.start_ms for i in unblocked), tz) if unblocked else None,
        "blocked_count": len(items) - len(unblocked),
        "attacked_workloads": len({(i.namespace, i.pod) for i in items}),
        "total_workloads": await _running_pods(request, f.namespace),
    }
    for lv in ALLOWED_LEVELS:
        out[f"level_{lv}_count"] = sum(1 for i in items if i.level == lv)
    return out


@router.get("/incidents/by-workload")
async def by_workload(request: Request, f: Filters) -> list[dict]:
    groups: dict[str, dict] = {}
    for i in await _store(request).query(f):
        g = groups.setdefault(i.pod, {"pod": i.pod, "blocked": 0, "unblocked": 0, "total": 0})
        g["unblocked" if _is_unblocked(i.status) else "blocked"] += 1
        g["total"] += 1
    rows = sorted(groups.values(), key=lambda g: (-g["unblocked"], -g["total"], g["pod"]))
    for g in rows:
        g["label"] = f"{g['total']}건" + (f" · 미차단 {g['unblocked']}" if g["unblocked"] else "")
    return rows


def _interval_ms(value: str) -> int:
    m = _INTERVAL_RE.fullmatch(value.strip())
    if not m or int(m.group(1)) == 0:
        raise ApiError(400, "invalid_interval", "interval은 30s, 5m, 1h 같은 형식이어야 합니다")
    return int(m.group(1)) * _UNIT_MS[m.group(2)]


@router.get("/incidents/timeseries")
async def timeseries(request: Request, f: Filters, interval: str = "5m") -> list[dict]:
    step = _interval_ms(interval)
    first = f.from_ms - f.from_ms % step
    n = (f.to_ms - first) // step + 1
    if n > MAX_BUCKETS:
        step = -(-(f.to_ms - first) // (MAX_BUCKETS - 1))  # 구간이 너무 많으면 간격을 늘린다
        first = f.from_ms - f.from_ms % step
        n = (f.to_ms - first) // step + 1
    buckets = [{"time_ms": first + k * step, "blocked": 0, "unblocked": 0} for k in range(n)]
    for i in await _store(request).query(f):
        k = (i.start_ms - first) // step
        if 0 <= k < n:
            buckets[k]["unblocked" if _is_unblocked(i.status) else "blocked"] += 1
    return buckets


@router.get("/incidents/{trace_id}")
async def get_incident(request: Request, trace_id: str) -> dict:
    tid = validate_trace_id(trace_id)
    inc = await _store(request).get(tid)
    if inc is None:
        raise ApiError(404, "not_found", "사건이 없습니다")
    return to_model(inc, request.app.state.settings.display_tz)
