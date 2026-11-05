"""정책 API (5.2): ① 정책 상태 · 방어가 제대로 도는가."""

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app import policies
from app.core.params import ALLOWED_LEVELS, CommonFilters, common_filters
from app.routers.infra import _cached, _falco_rules, _k8s, _tracing_policies

log = logging.getLogger(__name__)
router = APIRouter(tags=["policies"])

CACHE_SEC = 30


async def _hits(request: Request, f: CommonFilters) -> dict:
    """시간 범위 안 정책·룰별 탐지 수. 1초 안에 반복된 같은 행위는 1건(수집기가 접어 둔 detections 표).

    /policies/stats와 /policies/levels가 같이 쓴다 (30초 캐시).
    """
    k8s = request.app.state.k8s
    store = request.app.state.incidents

    async def build():
        rules_text = (await _falco_rules(request, k8s))[0] if k8s is not None else ""
        h = await store.detection_counts(f.from_ms * 1_000_000, f.to_ms * 1_000_000, f.namespace)
        prio = policies.falco_rule_priorities(rules_text)  # 룰 정의 우선, 없으면 경보의 priority
        for rule, p in h["falco_priority"].items():
            prio.setdefault(rule, p)
        return {"rules_text": rules_text, "tetragon": h["tetragon"], "falco": h["falco"], "falco_priority": prio}

    key = f"hits:{f.namespace}:{f.from_ms // 30000}:{f.to_ms // 30000}"
    return await _cached(request, key, CACHE_SEC, build)


async def _current_policies(request: Request, f: CommonFilters) -> list[dict]:
    """지금 클러스터에 있는 TracingPolicy. namespace를 주면 다른 namespace의 TracingPolicyNamespaced는 뺀다."""
    tps = await _tracing_policies(_k8s(request))
    if f.namespace:
        tps = [tp for tp in tps if tp.get("kind") != "TracingPolicyNamespaced"
               or (tp.get("metadata") or {}).get("namespace") == f.namespace]
    return tps


@router.get("/policies/stats")
async def stats(request: Request, f: Annotated[CommonFilters, Depends(common_filters)]) -> list[dict]:
    levels = request.app.state.sigma_levels
    tps, h = await asyncio.gather(_current_policies(request, f), _hits(request, f))
    prio = h["falco_priority"]
    rows = policies.tetragon_rows(tps, h["tetragon"], levels.tetragon) + policies.falco_rows(
        policies.falco_rule_names(h["rules_text"]), h["falco"], lambda r: levels.falco(r, prio.get(r, "")))
    return sorted(rows, key=lambda r: (-r["hits"], r["policy"]))


@router.get("/policies/levels")
async def level_counts(request: Request, f: Annotated[CommonFilters, Depends(common_filters)]) -> dict:
    """① 경고 단계별 탐지 · 로그 기준. 사건 수가 아니라 탐지 1건(1초 안 반복은 접음)을 1로 센다.

    Tetragon은 지금 클러스터에 있는 TracingPolicy의 로그만 센다(옛 테스트 정책 로그는 Loki에 남아 있어도 뺀다).
    Falco는 모든 룰을 세되 자체 상태 경보는 뺀다.
    """
    levels = request.app.state.sigma_levels
    tps, h = await asyncio.gather(_current_policies(request, f), _hits(request, f))
    current = {tp["metadata"]["name"] for tp in tps}
    counts = dict.fromkeys(ALLOWED_LEVELS, 0)
    def add(level: str, n: int) -> None:
        counts[level if level in counts else "informational"] += n

    for policy, n in h["tetragon"].items():
        if policy in current:
            add(levels.tetragon(policy), n)
    for rule, n in h["falco"].items():
        if not rule.startswith(policies.FALCO_INTERNAL):
            add(levels.falco(rule, h["falco_priority"].get(rule, "")), n)
    return {"total": sum(counts.values()), **{f"level_{k}_count": v for k, v in counts.items()}}
