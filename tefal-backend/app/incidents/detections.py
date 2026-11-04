"""탐지 수 수집 (① 경고 단계별 탐지 · 정책 상태 히트).

Loki의 Tetragon(정책이 걸린 이벤트)·Falco 로그를 구간별로 읽어, 1초 안에 반복된 같은 행위를 접은
"탐지 1건"을 DB에 쌓는다(dedup.py). API는 이 표를 센다.

화면마다 원본 줄을 Loki에서 다시 읽어 접으면 범위가 길 때(7일) Loki 조회가 시간 초과로 실패해서
사건 수집기처럼 커서를 두고 조금씩 읽는다.
"""

import json
import logging
import time

from app.config import Settings
from app.incidents import dedup
from app.incidents.store import IncidentStore
from app.incidents.tetragon import parse_event, parse_time_ns

log = logging.getLogger(__name__)

NS = 1_000_000_000
CURSOR_KEY = "detections_cursor_ns"
# 한 번에 받는 줄 수. 줄이 큰 구간(10분 11MB)에서 5000줄 요청은 Loki가 2분 넘게 응답하지 않아 작게 받는다
LOKI_LIMIT = 1000
RETENTION_DAYS = 30


class DetectionCollector:
    def __init__(self, settings: Settings, store: IncidentStore, loki) -> None:
        self.s = settings
        self.store = store
        self.loki = loki
        self.gap_ns = int(settings.dedup_gap_sec * NS)
        self._lag_ns = (settings.correlate_merge_sec + 5) * NS
        # 구간 경계에 걸친 반복을 이어 붙이려고 최근 묶음을 기억한다: key → (rowid, last_ns)
        self._open: dict[tuple, tuple[int, int]] = {}

    def _queries(self) -> tuple[str, str]:
        return (self.s.loki_tetragon_selector + ' |= "policy_name"',
                self.s.loki_falco_selector + ' |= `"rule"`')

    async def step(self, now_ns: int | None = None) -> bool:
        """한 구간을 처리한다. 더 읽을 구간이 남았으면 True."""
        now_ns = now_ns or time.time_ns()
        raw = await self.store.get_state(CURSOR_KEY)
        cursor = int(raw) if raw else now_ns - int(self.s.collect_backfill_hours * 3600 * NS)
        end = min(cursor + self.s.collect_chunk_sec * NS, now_ns - self._lag_ns)
        if end - cursor < NS:
            return False

        tq, fq = self._queries()
        tet = await self.loki.query_range(tq, cursor, end, limit=LOKI_LIMIT)
        fal = await self.loki.query_range(fq, cursor, end, limit=LOKI_LIMIT)
        # 한도에 걸린 쪽이 있으면 그 마지막 타임스탬프 직전까지만 처리하고 거기서 다시 읽는다
        for lines in (tet, fal):
            if len(lines) >= LOKI_LIMIT and lines[-1][0] > cursor:
                end = min(end, lines[-1][0])
        tet = [x for x in tet if x[0] < end]
        fal = [x for x in fal if x[0] < end]

        await self._save_tetragon(tet)
        await self._save_falco(fal)
        await self.store.set_state(CURSOR_KEY, str(end))
        await self.store.prune_detections(now_ns - RETENTION_DAYS * 86400 * NS)
        await self.store.commit()
        self._open = {k: v for k, v in self._open.items() if end - v[1] <= self.gap_ns + self._lag_ns}
        return end < now_ns - self._lag_ns - NS

    async def _add(self, key: tuple, source: str, name: str, namespace: str | None, priority: str | None,
                   run: dedup.Run) -> None:
        prev = self._open.get(key)
        if prev is not None and run.first_ns - prev[1] <= self.gap_ns:
            await self.store.extend_detection(prev[0], run.count, run.last_ns)
            self._open[key] = (prev[0], max(prev[1], run.last_ns))
            return
        rowid = await self.store.add_detection(source, name, namespace, priority, run.first_ns, run.last_ns, run.count)
        self._open[key] = (rowid, run.last_ns)

    async def _save_tetragon(self, lines: list[tuple[int, str]]) -> None:
        evs = [e for _, line in lines if (e := parse_event(line)) and e.policy]
        for run in dedup.collapse(evs, dedup.tetragon_key, lambda e: e.time_ns, self.gap_ns):
            e = run.first
            await self._add(("t", *dedup.tetragon_key(e)), "tetragon", e.policy, e.namespace or None, None, run)

    async def _save_falco(self, lines: list[tuple[int, str]]) -> None:
        alerts = []
        for loki_ns, line in lines:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict) or not d.get("rule"):
                continue
            of = d.get("output_fields") or {}
            t = parse_time_ns(d.get("time") or "") or loki_ns
            key = dedup.falco_key(str(of.get("k8s.pod.name") or ""), d["rule"],
                                  str(of.get("proc.cmdline") or ""), str(of.get("fd.name") or ""))
            alerts.append((t, key, d["rule"], d.get("priority") or None, of.get("k8s.ns.name") or None))
        for run in dedup.collapse(alerts, lambda a: a[1], lambda a: a[0], self.gap_ns):
            _, key, rule, prio, ns = run.first
            await self._add(("f", *key), "falco", rule, ns, prio, run)
