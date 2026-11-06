"""사건 저장소 (SQLite, 4.6). 캐시와 같은 DB 파일을 쓰고 연결만 따로 연다."""

import json
import os
import time
from dataclasses import dataclass, field

import aiosqlite

from app.core.params import CommonFilters

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    trace_id       TEXT PRIMARY KEY,
    start_ms       INTEGER NOT NULL,
    anchor_ms      INTEGER NOT NULL,
    last_ms        INTEGER NOT NULL,
    status         TEXT NOT NULL,          -- blocked | unblocked | pending
    level          TEXT NOT NULL,
    level_source   TEXT,
    action         TEXT NOT NULL,          -- Sigkill | Override | Detected
    detected_by    TEXT NOT NULL,          -- tetragon | falco | tetragon+falco
    namespace      TEXT NOT NULL,
    pod            TEXT NOT NULL,
    node           TEXT NOT NULL,
    runtime        TEXT,
    runtime_detail TEXT,
    summary        TEXT NOT NULL,
    mitre          TEXT NOT NULL DEFAULT '[]',
    src_ip         TEXT,
    exec_id        TEXT,
    parent_exec_id TEXT,
    policy         TEXT,
    container_id   TEXT NOT NULL DEFAULT '',
    falco_rules    TEXT NOT NULL DEFAULT '[]',
    falco_ms       INTEGER,                -- 처음 받은 Falco 경보 시각
    beyla_trace_id TEXT,                   -- 연결된 Beyla HTTP trace (span link)
    beyla_link_confidence TEXT,            -- high | low
    beyla_span_id  TEXT,
    updated_ms     INTEGER NOT NULL,
    layers         TEXT NOT NULL DEFAULT '[]',  -- 걸린 계층 합집합: app | proc | lsm | egress | falco (flow.py)
    layer_policies TEXT NOT NULL DEFAULT '{}',  -- 계층별 처음 걸린 정책·룰 이름
    false_positive TEXT                         -- 오탐 이유 (NULL = 정상). 화면·집계에서 뺀다 (falsepos.py)
);
CREATE INDEX IF NOT EXISTS incidents_start ON incidents(start_ms);
CREATE INDEX IF NOT EXISTS incidents_merge ON incidents(node, parent_exec_id, last_ms);
CREATE INDEX IF NOT EXISTS incidents_beyla ON incidents(beyla_trace_id);
CREATE TABLE IF NOT EXISTS members (
    trace_id      TEXT NOT NULL,
    exec_id       TEXT NOT NULL,
    event_time_ns INTEGER NOT NULL,
    event_type    TEXT NOT NULL,
    pid           INTEGER,
    PRIMARY KEY (trace_id, exec_id, event_time_ns, event_type)
);
CREATE INDEX IF NOT EXISTS members_pid ON members(pid);
CREATE TABLE IF NOT EXISTS falco_alerts (
    uuid        TEXT PRIMARY KEY,
    trace_id    TEXT,
    received_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS exported_spans (  -- Tempo에 이미 보낸 span (다시 보내면 중복 span이 된다)
    trace_id TEXT NOT NULL,
    span_id  TEXT NOT NULL,
    PRIMARY KEY (trace_id, span_id)
);
CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detections (  -- 탐지 1건 = 1초 안 반복을 접은 묶음 (dedup.py). ① 탐지 수
    source    TEXT NOT NULL,              -- tetragon | falco
    name      TEXT NOT NULL,              -- 정책 이름 | 룰 이름
    namespace TEXT,
    priority  TEXT,                       -- Falco priority
    first_ns  INTEGER NOT NULL,
    last_ns   INTEGER NOT NULL,
    count     INTEGER NOT NULL,           -- 접힌 원본 줄 수
    false_positive TEXT                   -- 오탐 이유 (NULL = 정상). 탐지 수에서 뺀다
);
CREATE INDEX IF NOT EXISTS detections_first ON detections(first_ns);
CREATE TABLE IF NOT EXISTS remote_ips (  -- 감시 pod가 밖으로 연결한 공인 IP (③ TI 대상, 5.4)
    ip        TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod       TEXT NOT NULL,
    source    TEXT NOT NULL,              -- tetragon | falco
    port      INTEGER,
    first_ns  INTEGER NOT NULL,
    last_ns   INTEGER NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (ip, pod, source)
);
"""

COLUMNS = ["trace_id", "start_ms", "anchor_ms", "last_ms", "status", "level", "level_source", "action", "detected_by", "namespace", "pod", "node", "runtime", "runtime_detail", "summary", "mitre", "src_ip", "exec_id", "parent_exec_id", "policy", "container_id", "falco_rules", "falco_ms", "beyla_trace_id", "beyla_link_confidence", "beyla_span_id", "updated_ms", "layers", "layer_policies", "false_positive"]
_JSON_COLS = {"mitre", "falco_rules", "layers", "layer_policies"}


@dataclass
class Incident:
    trace_id: str
    start_ms: int
    anchor_ms: int
    last_ms: int
    status: str
    level: str
    level_source: str | None
    action: str
    detected_by: str
    namespace: str
    pod: str
    node: str
    runtime: str | None
    runtime_detail: str | None
    summary: str
    mitre: list[str] = field(default_factory=list)
    src_ip: str | None = None
    exec_id: str | None = None
    parent_exec_id: str | None = None
    policy: str | None = None
    container_id: str = ""
    falco_rules: list[str] = field(default_factory=list)
    falco_ms: int | None = None
    beyla_trace_id: str | None = None
    beyla_link_confidence: str | None = None
    beyla_span_id: str | None = None
    updated_ms: int = 0
    layers: list[str] = field(default_factory=list)
    layer_policies: dict[str, str] = field(default_factory=dict)
    false_positive: str | None = None
    member_count: int = 0


@dataclass(frozen=True)
class Member:
    exec_id: str
    event_time_ns: int
    event_type: str
    pid: int | None


def _row_to_incident(row: aiosqlite.Row, member_count: int = 0) -> Incident:
    d = {c: row[c] for c in COLUMNS}
    for c in _JSON_COLS:
        d[c] = json.loads(d[c] or ("{}" if c == "layer_policies" else "[]"))
    return Incident(**d, member_count=member_count)


_ADDED_COLUMNS = {"beyla_trace_id": "TEXT", "beyla_link_confidence": "TEXT", "beyla_span_id": "TEXT",
                  "layers": "TEXT NOT NULL DEFAULT '[]'", "layer_policies": "TEXT NOT NULL DEFAULT '{}'",
                  "false_positive": "TEXT"}


async def _migrate(conn: aiosqlite.Connection) -> None:
    """이전 버전 DB에 없는 열을 더한다."""
    async with conn.execute("PRAGMA table_info(incidents)") as cur:
        have = {r[1] for r in await cur.fetchall()}
    for col, typ in _ADDED_COLUMNS.items():
        if col not in have:
            await conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {typ}")


class IncidentStore:
    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn

    @classmethod
    async def open(cls, path: str) -> "IncidentStore":
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        conn = await aiosqlite.connect(path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA busy_timeout=5000")
        # incidents 표만 먼저 만들고(있으면 그대로) 빠진 열을 더한 뒤 나머지(색인 포함)를 만든다
        await conn.executescript(_SCHEMA.split("CREATE INDEX")[0])
        await _migrate(conn)
        await conn.executescript(_SCHEMA)
        async with conn.execute("PRAGMA table_info(detections)") as cur:
            if "false_positive" not in {r[1] for r in await cur.fetchall()}:
                await conn.execute("ALTER TABLE detections ADD COLUMN false_positive TEXT")
        await conn.commit()
        return cls(conn)

    async def close(self) -> None:
        await self._conn.close()

    async def commit(self) -> None:
        await self._conn.commit()

    # ---- state ----
    async def get_state(self, key: str) -> str | None:
        async with self._conn.execute("SELECT value FROM state WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def set_state(self, key: str, value: str) -> None:
        await self._conn.execute(
            "INSERT INTO state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- 쓰기 ----
    async def save(self, inc: Incident) -> None:
        inc.updated_ms = int(time.time() * 1000)
        vals = [json.dumps(getattr(inc, c), ensure_ascii=False) if c in _JSON_COLS else getattr(inc, c) for c in COLUMNS]
        sets = ", ".join(f"{c}=excluded.{c}" for c in COLUMNS[1:])
        await self._conn.execute(
            f"INSERT INTO incidents({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))}) "
            f"ON CONFLICT(trace_id) DO UPDATE SET {sets}",
            vals,
        )

    async def add_members(self, trace_id: str, members: list[Member]) -> None:
        await self._conn.executemany(
            "INSERT OR IGNORE INTO members(trace_id, exec_id, event_time_ns, event_type, pid) VALUES (?,?,?,?,?)",
            [(trace_id, m.exec_id, m.event_time_ns, m.event_type, m.pid) for m in members],
        )

    async def move_members(self, src: str, dst: str) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO members(trace_id, exec_id, event_time_ns, event_type, pid) "
            "SELECT ?, exec_id, event_time_ns, event_type, pid FROM members WHERE trace_id=?",
            (dst, src),
        )
        await self._conn.execute("DELETE FROM members WHERE trace_id=?", (src,))
        await self._conn.execute("DELETE FROM incidents WHERE trace_id=?", (src,))
        await self._conn.execute("UPDATE falco_alerts SET trace_id=? WHERE trace_id=?", (dst, src))

    async def unsent_spans(self, trace_id: str, spans: list[dict]) -> list[dict]:
        if not spans:
            return []
        ids = [sp["spanId"] for sp in spans]
        async with self._conn.execute(
            f"SELECT span_id FROM exported_spans WHERE trace_id=? AND span_id IN ({','.join('?' * len(ids))})",
            (trace_id, *ids),
        ) as cur:
            sent = {r[0] for r in await cur.fetchall()}
        return [sp for sp in spans if sp["spanId"] not in sent]

    async def mark_exported(self, trace_id: str, spans: list[dict]) -> None:
        await self._conn.executemany(
            "INSERT OR IGNORE INTO exported_spans(trace_id, span_id) VALUES (?,?)",
            [(trace_id, sp["spanId"]) for sp in spans],
        )

    async def falco_seen(self, uuid: str) -> str | None:
        async with self._conn.execute("SELECT trace_id FROM falco_alerts WHERE uuid=?", (uuid,)) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def record_falco(self, uuid: str, trace_id: str | None) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO falco_alerts(uuid, trace_id, received_ms) VALUES (?,?,?)",
            (uuid, trace_id, int(time.time() * 1000)),
        )

    async def finalize_pending(self, before_ms: int) -> list[Incident]:
        """Falco 경보 뒤 차단이 오지 않은 사건을 unblocked로 확정하고 확정한 사건을 돌려준다."""
        async with self._conn.execute(
            "UPDATE incidents SET status='unblocked', updated_ms=? WHERE status='pending' AND falco_ms < ? "
            "RETURNING *",
            (int(time.time() * 1000), before_ms),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_incident(r) for r in rows]

    # ---- 조회 ----
    async def get(self, trace_id: str) -> Incident | None:
        async with self._conn.execute("SELECT * FROM incidents WHERE trace_id=?", (trace_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return _row_to_incident(row, await self.member_count(trace_id))

    async def member_keys(self, trace_id: str) -> set[tuple[str, int, str]]:
        """사건에 묶인 이벤트 키 (exec_id, event_time_ns, event_type). AI 입력을 Loki에서 다시 읽을 때 쓴다."""
        async with self._conn.execute(
            "SELECT exec_id, event_time_ns, event_type FROM members WHERE trace_id=?", (trace_id,)
        ) as cur:
            return {(r[0], r[1], r[2]) for r in await cur.fetchall()}

    async def member_count(self, trace_id: str) -> int:
        async with self._conn.execute("SELECT COUNT(*) FROM members WHERE trace_id=?", (trace_id,)) as cur:
            return (await cur.fetchone())[0]

    async def find_mergeable(self, node: str, parent_exec_id: str, since_ms: int) -> Incident | None:
        """같은 부모 아래 최근 Tetragon 사건 (배치 경계를 넘는 연속 차단 병합)."""
        async with self._conn.execute(
            "SELECT * FROM incidents WHERE node=? AND parent_exec_id=? AND last_ms>=? "
            "AND detected_by!='falco' ORDER BY last_ms DESC LIMIT 1",
            (node, parent_exec_id, since_ms),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_incident(row) if row else None

    async def find_by_beyla(self, beyla_trace_id: str, pod: str) -> Incident | None:
        """같은 HTTP 요청(Beyla trace)에 연결된 사건: 한 요청 = 한 사건."""
        async with self._conn.execute(
            "SELECT * FROM incidents WHERE beyla_trace_id=? AND pod=? ORDER BY anchor_ms LIMIT 1",
            (beyla_trace_id, pod),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_incident(row) if row else None

    async def find_by_lineage(
        self, container_id: str, pids: set[int], lo_ms: int, hi_ms: int, *, falco_only: bool
    ) -> Incident | None:
        """같은 컨테이너에서 계보 pid가 겹치는 사건. falco_only면 Falco로만 만든 사건, 아니면 Tetragon 사건."""
        if not container_id or not pids:
            return None
        marks = ",".join("?" * len(pids))
        cond = "i.detected_by='falco'" if falco_only else "i.detected_by!='falco'"
        async with self._conn.execute(
            f"SELECT DISTINCT i.* FROM incidents i JOIN members m ON m.trace_id=i.trace_id "
            f"WHERE substr(i.container_id,1,12)=? AND m.pid IN ({marks}) AND {cond} AND i.false_positive IS NULL "
            f"AND i.anchor_ms BETWEEN ? AND ? ORDER BY i.anchor_ms LIMIT 1",
            (container_id[:12], *sorted(pids), lo_ms, hi_ms),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_incident(row) if row else None

    # ---- 탐지 (① 탐지 수) ----
    async def add_detection(self, source: str, name: str, namespace: str | None, priority: str | None,
                            first_ns: int, last_ns: int, count: int) -> int:
        cur = await self._conn.execute(
            "INSERT INTO detections(source, name, namespace, priority, first_ns, last_ns, count) VALUES (?,?,?,?,?,?,?)",
            (source, name, namespace, priority, first_ns, last_ns, count),
        )
        return cur.lastrowid

    async def extend_detection(self, rowid: int, count: int, last_ns: int) -> None:
        await self._conn.execute(
            "UPDATE detections SET count = count + ?, last_ns = MAX(last_ns, ?) WHERE rowid = ?", (count, last_ns, rowid)
        )

    async def detection_counts(self, from_ns: int, to_ns: int, namespace: str | None) -> dict:
        """시간 범위 안에서 시작한 탐지 수: {"tetragon": {정책: n}, "falco": {룰: n}, "falco_priority": {룰: p}}."""
        where, args = ["first_ns BETWEEN ? AND ?", "false_positive IS NULL"], [from_ns, to_ns]
        if namespace:
            where.append("namespace = ?")
            args.append(namespace)
        out: dict = {"tetragon": {}, "falco": {}, "falco_priority": {}}
        async with self._conn.execute(
            f"SELECT source, name, COUNT(*), MAX(priority) FROM detections WHERE {' AND '.join(where)} GROUP BY source, name",
            args,
        ) as cur:
            for source, name, n, prio in await cur.fetchall():
                out[source][name] = n
                if source == "falco" and prio:
                    out["falco_priority"][name] = prio
        return out

    async def falco_detections(self) -> list[dict]:
        """오탐 판정 전 Falco 탐지 행 (지난 데이터 오탐 표시용)."""
        async with self._conn.execute(
            "SELECT rowid, name, namespace, first_ns, last_ns FROM detections "
            "WHERE source='falco' AND false_positive IS NULL ORDER BY first_ns"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def mark_detection_fp(self, rowid: int, reason: str) -> None:
        await self._conn.execute("UPDATE detections SET false_positive=? WHERE rowid=?", (reason, rowid))

    async def prune_detections(self, before_ns: int) -> None:
        await self._conn.execute("DELETE FROM detections WHERE first_ns < ?", (before_ns,))
        await self._conn.execute("DELETE FROM remote_ips WHERE last_ns < ?", (before_ns,))

    # ---- 외부 연결 (③ TI 대상) ----
    async def add_remote_ip(self, ip: str, namespace: str, pod: str, source: str, port: int | None, t_ns: int) -> None:
        await self._conn.execute(
            "INSERT INTO remote_ips(ip, namespace, pod, source, port, first_ns, last_ns, count) VALUES (?,?,?,?,?,?,?,1) "
            "ON CONFLICT(ip, pod, source) DO UPDATE SET count = count + 1, "
            "first_ns = MIN(first_ns, excluded.first_ns), last_ns = MAX(last_ns, excluded.last_ns), "
            "port = COALESCE(excluded.port, port)",
            (ip, namespace, pod, source, port, t_ns, t_ns),
        )

    async def remote_ips(self, from_ns: int, to_ns: int, namespace: str | None = None) -> list[dict]:
        where, args = ["last_ns >= ? AND first_ns <= ?"], [from_ns, to_ns]
        if namespace:
            where.append("namespace = ?")
            args.append(namespace)
        async with self._conn.execute(
            f"SELECT ip, namespace, pod, source, port, first_ns, last_ns, count FROM remote_ips WHERE {' AND '.join(where)}",
            args,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def runtimes_by_pod(self) -> dict[str, str]:
        """사건에서 확인된 pod별 런타임 (④ 워크로드 표)."""
        async with self._conn.execute(
            "SELECT pod, runtime FROM incidents WHERE runtime IS NOT NULL GROUP BY pod"
        ) as cur:
            return {r[0]: r[1] for r in await cur.fetchall()}

    async def query(self, f: CommonFilters, limit: int | None = None, include_fp: bool = False) -> list[Incident]:
        where, args = ["start_ms BETWEEN ? AND ?"], [f.from_ms, f.to_ms]
        if not include_fp:
            where.append("false_positive IS NULL")  # 오탐 표시된 사건은 화면·집계에서 뺀다
        if f.namespace:
            where.append("namespace=?")
            args.append(f.namespace)
        if f.runtimes:
            where.append(f"lower(runtime) IN ({','.join('?' * len(f.runtimes))})")
            args += sorted(f.runtimes)
        if f.status:
            where.append("status=?")
            args.append(f.status)
        if f.levels:
            where.append(f"level IN ({','.join('?' * len(f.levels))})")
            args += sorted(f.levels)
        sql = (
            "SELECT i.*, (SELECT COUNT(*) FROM members m WHERE m.trace_id=i.trace_id) AS mc "
            f"FROM incidents i WHERE {' AND '.join(where)} "
            # 미차단(판정 중 포함) 먼저, 그다음 최신순
            "ORDER BY CASE WHEN status='blocked' THEN 1 ELSE 0 END, start_ms DESC"
        )
        if limit:
            sql += " LIMIT ?"
            args.append(limit)
        async with self._conn.execute(sql, args) as cur:
            rows = await cur.fetchall()
        return [_row_to_incident(r, r["mc"]) for r in rows]
