"""① 계층별 방어 흐름 API (`/flow/summary`). 사건 기준 집계.

- 칸 숫자 = 그 계층이 `layers`에 들어 있는 사건 수.
- 그 런타임 pod에 걸린 그 계층 정책이 클러스터에 없으면 `null`("해당 없음"). K8s API를 못 쓰면 모두 있다고 본다.
- `Falco 탐지` = Tetragon 계층 없이 Falco로만 잡힌 사건.
- `html` = ① 패널(Business Text)이 그대로 넣는 화면 (`app/flow_view.py`, 목업 mockups/flow 기준).
- `recent` = 최근 5분 안에 시작한 사건 기준. `last_block_ms` = 최근 7일 안 마지막 차단 사건.
- 정합성: 줄별 blocked 합 = `/incidents/summary`의 blocked_count, unblocked 합 = unblocked_count.
  런타임을 모르는 Tetragon 사건이 있으면 `기타` 줄로 넣어 합이 맞게 한다.
"""

import asyncio
import time
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app import flow, flow_view, infra
from app.core.params import CommonFilters, common_filters
from app.core.timefmt import fmt_relative_ko
from app.routers.infra import _cached, _network_policies, _tracing_policies

router = APIRouter(tags=["flow"])

CACHE_SEC = 30
RECENT_MS = 5 * 60 * 1000
LAST_BLOCK_RANGE_MS = 7 * 86400 * 1000
CELLS = ("app", "proc", "lsm", "egress")
OTHER = flow.OTHER
KEY = {"PHP": "php", "Java": "java", "Node": "node", flow.FALCO_ONLY: "falco", OTHER: "other"}


def policy_layer(tp: dict) -> str | None:
    spec = tp.get("spec") or {}
    if "egress" in (tp.get("metadata") or {}).get("name", "").lower():
        return "egress"
    if spec.get("lsmhooks") and infra.is_block_policy(tp):
        return "lsm"
    if spec.get("uprobes"):
        return "app"
    if spec.get("kprobes") or spec.get("tracepoints"):
        return "proc"
    return None


async def available_layers(request: Request, namespace: str | None) -> dict[str, set[str]] | None:
    """런타임별로 클러스터에 걸려 있는 계층. K8s API를 못 쓰면 None(=모두 있다고 본다)."""
    k8s = request.app.state.k8s
    if k8s is None:
        return None
    ns = namespace or (request.app.state.settings.watch_namespace_list or ["default"])[0]
    pods, tps, cnps, known = await asyncio.gather(
        k8s.items(f"/api/v1/namespaces/{ns}/pods"), _tracing_policies(k8s), _network_policies(k8s),
        request.app.state.incidents.runtimes_by_pod())
    out: dict[str, set[str]] = {}
    for pod in pods:
        rt = infra.runtime_of(pod, known)
        if rt not in flow.RUNTIMES:
            continue
        have = out.setdefault(rt, set())
        have |= {layer for tp in tps if infra.policy_applies(tp, pod) and (layer := policy_layer(tp))}
        labels = (pod.get("metadata") or {}).get("labels") or {}
        if any("egress" in c["metadata"]["name"] and infra.selector_matches(
                (c.get("spec") or {}).get("endpointSelector"), labels) for c in cnps):
            have.add("egress")
    return out


def build_rows(incs: list, now_ms: int, avail: dict[str, set[str]] | None, last_block: dict[str, int]) -> list[dict]:
    groups: dict[str, list] = {}
    for inc in incs:
        groups.setdefault(flow.row_key(inc), []).append(inc)
    rows = []
    for name in (*flow.RUNTIMES, flow.FALCO_ONLY, OTHER):
        items = groups.get(name, [])
        if name == OTHER and not items:
            continue
        recent = [i for i in items if now_ms - i.start_ms <= RECENT_MS]
        row = {"runtime": name, "incidents": len(items),
               "blocked": sum(i.status == "blocked" for i in items),
               "unblocked": sum(i.status != "blocked" for i in items),
               "recent": {"incidents": len(recent)}, "policy": {},
               "last_block_ms": last_block.get(name)}
        if name in flow.RUNTIMES:
            have = avail.get(name, set()) if avail is not None else set(CELLS)
            for layer in CELLS:
                hit = [i for i in items if layer in i.layers]
                if layer not in have and not hit:
                    row[layer] = None  # 그 런타임에 그 계층 정책이 없다
                    row["recent"][layer] = None
                    continue
                row[layer] = len(hit)
                row["recent"][layer] = sum(1 for i in recent if layer in i.layers)
                names = Counter(i.layer_policies.get(layer) for i in hit if i.layer_policies.get(layer))
                row["policy"][layer] = flow.short_policy(names.most_common(1)[0][0]) if names else None
        rows.append(row)
    return rows


def flat(rows: list[dict], last_block_ms: int | None, now_ms: int) -> dict:
    """Canvas 패널용 한 줄 데이터. 칸마다 숫자(색), 표시 글자, 최근 5분 여부(테두리)를 준다."""
    out: dict = {}
    for r in rows:
        k = KEY[r["runtime"]]
        for f in ("incidents", "blocked", "unblocked"):
            out[f"{k}_{f}"] = r[f]
        out[f"{k}_blocked_text"] = f"차단 {r['blocked']}"
        out[f"{k}_unblocked_text"] = f"미차단 {r['unblocked']}"
        out[f"{k}_recent"] = r["recent"]["incidents"]
        for layer in CELLS:
            if layer not in r:
                continue
            v = r[layer]
            out[f"{k}_{layer}"] = v
            out[f"{k}_{layer}_text"] = "해당 없음" if v is None else str(v)
            out[f"{k}_{layer}_recent"] = r["recent"].get(layer) or 0
            out[f"{k}_{layer}_policy"] = r["policy"].get(layer) or ""
    out["last_block_ms"] = last_block_ms
    out["last_block_text"] = f"마지막 차단 {fmt_relative_ko(last_block_ms, now_ms)}" if last_block_ms else "최근 7일 차단 없음"
    return out


@router.get("/flow/summary")
async def summary(request: Request, f: Annotated[CommonFilters, Depends(common_filters)]) -> dict:
    store = request.app.state.incidents

    async def build():
        now_ms = int(time.time() * 1000)
        # 사건 필터 중 namespace·시간 범위만 적용한다(런타임·상태는 줄과 칸 자체가 나눈다)
        base = CommonFilters(f.from_ms, f.to_ms, f.namespace, None, None)
        incs, week, avail = await asyncio.gather(
            store.query(base),
            store.query(CommonFilters(now_ms - LAST_BLOCK_RANGE_MS, now_ms, f.namespace, None, None)),
            available_layers(request, f.namespace))
        last_block: dict[str, int] = {}
        for i in week:
            if i.status == "blocked":
                k = flow.row_key(i)
                last_block[k] = max(last_block.get(k, 0), i.start_ms)
        rows = build_rows(incs, now_ms, avail, last_block)
        last = max(last_block.values(), default=None)
        fl = flat(rows, last, now_ms)
        tz = request.app.state.settings.display_tz
        feed = sorted(incs, key=lambda i: i.start_ms, reverse=True)
        live = any(now_ms - i.start_ms <= RECENT_MS for i in incs)
        html = flow_view.render(rows, feed, fl["last_block_text"],
                                flow_view.range_text(f.from_ms, f.to_ms, now_ms, tz),
                                flow_view.link_range(f.from_ms, f.to_ms, now_ms), tz, live, now_ms)
        return {"rows": rows, "last_block_ms": last, "flat": fl, "html": html}

    key = f"flow:{f.namespace}:{f.from_ms // 30000}:{f.to_ms // 30000}"
    return await _cached(request, key, CACHE_SEC, build)
