"""Loki의 Tetragon 로그를 주기적으로 읽어 사건을 만든다 (4.1 ~ 4.3).

- 커서(Loki 타임스탬프 ns)를 DB에 저장해 재시작해도 이어서 읽는다.
- 병합 대기(CORRELATE_MERGE_SEC)보다 오래된 구간만 처리한다. 그래서 연속 차단이 한 배치 안에서
  묶이고, Tetragon 사건은 바로 확정(blocked)된다.
"""

import asyncio
import logging
import re
import time

import httpx
from prometheus_client import Counter, Gauge

from app.config import Settings
from app.incidents import correlate
from app.incidents.builder import log_incident, save_cluster
from app.incidents.events import LOKI_INGEST_LAG_SEC
from app.incidents.levels import SigmaLevels
from app.incidents.store import IncidentStore
from app.incidents.tempo import TempoClient
from app.incidents.tetragon import TetragonEvent, parse_event

log = logging.getLogger(__name__)

NS = 1_000_000_000
LOKI_LIMIT = 5000
CURSOR_KEY = "tetragon_cursor_ns"
_POD_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")  # LogQL에 넣기 전 검증

INCIDENTS = Counter("tefal_incidents_total", "사건 생성/병합 수", ["source", "result"])  # result: created | merged
COLLECTOR_LAG = Gauge("tefal_collector_lag_seconds", "Tetragon 수집 커서와 현재 시각의 차이")
COLLECTOR_ERRORS = Counter("tefal_collector_errors_total", "수집 실패 횟수")


class LokiClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str) -> None:
        self._http = http
        self._url = base_url.rstrip("/") + "/loki/api/v1/query_range"

    async def query_range(self, expr: str, start_ns: int, end_ns: int, limit: int = LOKI_LIMIT) -> list[tuple[int, str]]:
        r = await self._http.get(
            self._url,
            params={"query": expr, "start": start_ns, "end": end_ns, "limit": limit, "direction": "forward"},
            timeout=30.0,
        )
        r.raise_for_status()
        vals = [(int(t), line) for s in r.json()["data"]["result"] for t, line in s["values"]]
        return sorted(vals)


class Collector:
    def __init__(
        self,
        settings: Settings,
        store: IncidentStore,
        loki: LokiClient,
        levels: SigmaLevels,
        lock: asyncio.Lock | None = None,
        tempo: TempoClient | None = None,
        detections=None,
    ) -> None:
        self.tempo = tempo
        self.detections = detections  # DetectionCollector (① 탐지 수), 같은 루프에서 돈다
        self.s = settings
        self.lock = lock or asyncio.Lock()  # Falco 수신과 DB 쓰기를 겹치지 않게 한다
        self.store = store
        self.loki = loki
        self.levels = levels
        self._watch = set(settings.watch_namespace_list)
        self._lag_ns = (settings.correlate_merge_sec + 5) * NS

    async def run(self) -> None:
        while True:
            try:
                async with self.lock:
                    busy = await self.step()
                    if self.detections is not None:
                        busy = await self.detections.step() or busy
            except asyncio.CancelledError:
                raise
            except Exception:
                COLLECTOR_ERRORS.inc()
                log.exception("collector step 실패")
                busy = False
            await asyncio.sleep(0 if busy else self.s.collect_interval_sec)

    async def step(self, now_ns: int | None = None) -> bool:
        """한 구간을 처리한다. 더 읽을 구간이 남았으면 True."""
        now_ns = now_ns or time.time_ns()
        raw = await self.store.get_state(CURSOR_KEY)
        cursor = int(raw) if raw else now_ns - int(self.s.collect_backfill_hours * 3600 * NS)
        end = min(cursor + self.s.collect_chunk_sec * NS, now_ns - self._lag_ns)
        COLLECTOR_LAG.set(max(0, now_ns - cursor) / NS)
        if end - cursor < NS:
            await self._finalize(cursor)
            return False

        lines = await self.loki.query_range(
            self.s.loki_tetragon_selector + ' |~ "KPROBE_ACTION_(SIGKILL|OVERRIDE)"', cursor, end
        )
        if len(lines) >= LOKI_LIMIT:
            # 한도에 걸렸으면 마지막 타임스탬프 직전까지만 처리하고 그 지점부터 다시 읽는다
            last_ts = lines[-1][0]
            if last_ts > cursor:
                end = last_ts
                lines = [x for x in lines if x[0] < end]

        anchors = []
        for _, line in lines:
            ev = parse_event(line)
            if ev and ev.is_anchor and ev.namespace in self._watch:
                anchors.append(ev)

        for cluster in correlate.cluster_anchors(anchors, self.s.correlate_merge_sec):
            window = await self._window(cluster)
            _, created = await save_cluster(self.store, self.levels, self.s, cluster, window, self.tempo)
            INCIDENTS.labels("tetragon", "created" if created else "merged").inc()

        await self.store.set_state(CURSOR_KEY, str(end))
        await self._finalize(end)
        await self.store.commit()
        if anchors:
            log.info("collector: 기준점 %d건 처리 (%s ~ %s)", len(anchors), cursor, end)
        return end < now_ns - self._lag_ns - NS

    async def _window(self, cluster: correlate.AnchorCluster) -> list[TetragonEvent]:
        """기준점 전후로 같은 pod의 Tetragon 이벤트 (역조회)."""
        pod = cluster.first.pod
        if not _POD_RE.fullmatch(pod):
            return []
        start = cluster.first.time_ns - (self.s.correlate_lookback_sec + 5) * NS
        end = cluster.last.time_ns + LOKI_INGEST_LAG_SEC * NS
        lines = await self.loki.query_range(f'{self.s.loki_tetragon_selector} |= "{pod}"', start, end)
        out = []
        for _, line in lines:
            ev = parse_event(line)
            if ev and ev.pod == pod:
                out.append(ev)
        return out

    async def _finalize(self, cursor_ns: int) -> None:
        # Tetragon을 (Falco 경보 시각 + FALCO_WAIT_SEC)까지 다 읽었는데도 차단이 없으면 미차단 확정
        done = await self.store.finalize_pending(cursor_ns // 1_000_000 - self.s.falco_wait_sec * 1000)
        if done:
            log.info("collector: 판정 중 사건 %d건을 미차단으로 확정", len(done))
            await self.store.commit()
            for inc in done:
                log_incident(inc)
