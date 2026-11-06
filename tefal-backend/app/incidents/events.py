"""사건에 묶인 Tetragon 이벤트를 Loki에서 다시 읽는다 (AI 입력, 계층 채우기).

members 표에는 이벤트 키(exec_id, 시각, 종류)만 있어서 내용은 Loki에서 다시 읽는다.
Loki 타임스탬프는 수집 시각이라 이벤트보다 늦으므로 끝을 넉넉히 잡는다(LOKI_INGEST_LAG_SEC).
"""

import re

import httpx

from app.config import Settings
from app.incidents.store import Incident, IncidentStore
from app.incidents.tetragon import TetragonEvent, parse_event

NS = 1_000_000_000
# Loki 타임스탬프는 이벤트 시각이 아니라 수집 시각이라 수십 초 늦다(확인: 14:48:41 이벤트가 14:49:18).
# 사건 이벤트를 다시 읽을 때 끝을 이만큼 넉넉히 잡는다. 이벤트 시각으로 다시 거르므로 묶기 결과는 같다.
LOKI_INGEST_LAG_SEC = 120
_POD_RE = re.compile(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?")  # LogQL에 넣기 전 검증


async def incident_events(store: IncidentStore, loki, settings: Settings, inc: Incident) -> list[TetragonEvent]:
    keys = await store.member_keys(inc.trace_id)
    if not keys or not _POD_RE.fullmatch(inc.pod or ""):
        return []
    start = inc.start_ms * 1_000_000 - (settings.correlate_lookback_sec + 5) * NS
    end = inc.last_ms * 1_000_000 + LOKI_INGEST_LAG_SEC * NS
    lines = await loki.query_range(f'{settings.loki_tetragon_selector} |= "{inc.pod}"', start, end, limit=2000)
    return [e for _, line in lines if (e := parse_event(line)) and (e.process.exec_id, e.time_ns, e.event_type) in keys]


BACKFILL_KEY = "layers_backfill_v1"
MITRE_BACKFILL_KEY = "mitre_backfill_v1"


async def backfill_layers(store: IncidentStore, loki, settings: Settings, lock) -> int:
    """계층(layers)이 비어 있는 지난 사건을 한 번 채운다. 사건 DB를 다시 만들지 않으므로
    trace_id와 웹훅으로만 받은 Falco 사건이 그대로 남는다. 끝나면 state에 표시해 다시 하지 않는다."""
    import logging

    from app import flow
    from app.core.params import CommonFilters

    log = logging.getLogger(__name__)
    if await store.get_state(BACKFILL_KEY):
        return 0
    incs = [i for i in await store.query(CommonFilters(0, 2**62, None, None, None)) if not i.layers]
    done = 0
    for inc in incs:
        try:
            events = await incident_events(store, loki, settings, inc)
        except (httpx.HTTPError, KeyError, ValueError) as e:  # Loki 오류가 나도 다른 사건은 계속 채운다
            log.warning("계층 채우기: %s 이벤트 조회 실패 (%s)", inc.trace_id, type(e).__name__)
            continue
        async with lock:
            fresh = await store.get(inc.trace_id)
            if fresh is None or fresh.layers:
                continue
            flow.add_layers(fresh, events)
            for rule in fresh.falco_rules:
                flow.add_falco(fresh, rule)
            await store.save(fresh)
            done += 1
    async with lock:
        await store.set_state(BACKFILL_KEY, str(done))
        await store.commit()
    log.info("계층 채우기: 지난 사건 %d건 완료", done)
    return done


async def backfill_mitre(store: IncidentStore, levels, lock) -> int:
    """MITRE가 비어 있는 지난 사건을 한 번 채운다. 저장된 정책·규칙 이름에 표를 적용하므로 Loki를 읽지 않는다.
    (웹훅 tags는 저장하지 않았으므로 지난 Falco 사건은 표의 falco 절만 쓴다.)"""
    import logging

    from app.core.params import CommonFilters

    log = logging.getLogger(__name__)
    async with lock:
        if await store.get_state(MITRE_BACKFILL_KEY):
            return 0
        done = 0
        for inc in await store.query(CommonFilters(0, 2**62, None, None, None)):
            if inc.mitre:
                continue
            policies = [inc.policy, *(v for k, v in inc.layer_policies.items() if k != "falco")]
            ids = levels.mitre_of([p for p in policies if p], inc.falco_rules)
            if ids:
                inc.mitre = ids
                await store.save(inc)
                done += 1
        await store.set_state(MITRE_BACKFILL_KEY, str(done))
        await store.commit()
    log.info("MITRE 채우기: 지난 사건 %d건 완료", done)
    return done
