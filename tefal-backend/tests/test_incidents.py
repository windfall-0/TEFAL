"""사건 생성(수집기·묶기·Falco)과 /incidents API.

이벤트 형식은 실제 클러스터 Loki의 Tetragon export 줄(php2shell, 2026-11-04)을 줄여서 썼다.
"""

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.incidents import correlate
from app.incidents.collector import CURSOR_KEY, Collector, LokiClient
from app.incidents.falco import ingest_falco
from app.incidents.levels import SigmaLevels
from app.incidents.store import IncidentStore
from app.incidents.tetragon import parse_event, parse_time_ns

NS = 1_000_000_000
T0 = parse_time_ns("2026-11-04T02:45:25.122951607Z")
POD = "php2shell-b994795c-kj4rm"
CID = "7b5b068adfafc5452f4969e053f3157f642c0ffea809a960b6feb8868a7c22ef"

# exec_id → (host pid, 컨테이너 pid, parent exec_id, binary)
PROCS = {
    "init": (6872, 1, "shim", "/usr/sbin/apache2"),
    "worker": (7277, 23, "init", "/usr/sbin/apache2"),
    "child": (8001, 52, "worker", "/usr/sbin/apache2"),
    "child2": (8050, 60, "worker", "/usr/sbin/apache2"),
    "probe": (7994, 9, "shim", "/usr/bin/rm"),
}


def _iso(t_ns: int) -> str:
    sec, frac = divmod(t_ns, NS)
    return datetime.fromtimestamp(sec, UTC).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:09d}Z"


def _proc(eid: str, pod: str = POD) -> dict:
    pid, cpid, parent, binary = PROCS[eid]
    return {
        "exec_id": eid, "pid": pid, "binary": binary, "arguments": "-DFOREGROUND",
        "parent_exec_id": parent,
        "pod": {"namespace": "vuln-lab", "name": pod, "workload": "php2shell",
                "container": {"id": f"containerd://{CID}", "pid": cpid,
                              "image": {"name": "docker.io/library/dvwa:php8.5.11"}}},
    }


def line(etype: str, eid: str, dt: float, *, policy=None, action=None, file_arg=None, ns="vuln-lab") -> str:
    body = {"process": _proc(eid)}
    body["process"]["pod"]["namespace"] = ns
    parent = PROCS[eid][2]
    if parent in PROCS:
        body["parent"] = _proc(parent)
    if policy:
        body["policy_name"] = policy
        body["function_name"] = "bprm_check_security"
    if action:
        body["action"] = action
    if file_arg:
        body["args"] = [{"file_arg": {"path": file_arg}}]
    return json.dumps({etype: body, "node_name": "k8s-worker2", "time": _iso(T0 + int(dt * NS))})


BLOCK = {"policy": "php2shell-lsm-bprm-block", "action": "KPROBE_ACTION_OVERRIDE", "file_arg": "/usr/bin/dash"}


def attack_lines() -> list[str]:
    return [
        line("process_exec", "probe", -2.0),  # 같은 pod의 exec probe: 계보 밖
        line("process_uprobe", "worker", -0.00006, policy="php2shell-uprobe-zifsystem-observe", action="KPROBE_ACTION_POST"),
        line("process_kprobe", "child", -0.00002, policy="php2shell-kprobe-execve-observe", action="KPROBE_ACTION_POST"),
        line("process_lsm", "child", -0.00001, **BLOCK),
        line("process_lsm", "child", 0, **BLOCK),
        line("process_exit", "child", 0.00001),
    ]


# ---- 순수 로직 ----

def test_parse_time_ns_keeps_nanoseconds():
    assert parse_time_ns("2026-11-04T02:45:25.122951607Z") % NS == 122951607
    assert parse_time_ns("2026-11-04T02:45:25Z") % NS == 0
    assert parse_time_ns("garbage") is None


def test_parse_event_real_shape():
    ev = parse_event(line("process_lsm", "child", 0, **BLOCK))
    assert ev.is_anchor and ev.pod == POD and ev.node == "k8s-worker2"
    assert ev.process.container_pid == 52 and ev.parent.exec_id == "worker"
    assert ev.container_id == CID and ev.file_arg == "/usr/bin/dash"
    assert parse_event('{"process_exec":{"process":{"exec_id":"x"}}}') is None  # pod 없는 호스트 이벤트


def test_trace_id_deterministic_and_valid():
    a = correlate.make_trace_id("n", "e", 1)
    assert a == correlate.make_trace_id("n", "e", 1) and len(a) == 32
    assert a != correlate.make_trace_id("n", "e", 2)


def test_cluster_merges_within_merge_window_only():
    evs = [parse_event(line("process_lsm", "child", t, **BLOCK)) for t in (0, 5, 14, 30)]
    clusters = correlate.cluster_anchors(evs, merge_sec=10)
    assert [len(c.anchors) for c in clusters] == [3, 1]


def test_lineage_stops_before_container_init():
    evs = [parse_event(x) for x in attack_lines()]
    cluster = correlate.cluster_anchors([e for e in evs if e.is_anchor], 10)[0]
    ids = correlate.lineage(cluster, evs, max_depth=8)
    assert ids == {"child", "worker"}
    mem = correlate.members(cluster, evs, ids, lookback_sec=60)
    assert {m.process.exec_id for m in mem} == {"child", "worker"}
    assert len(mem) == 5  # probe 제외


def test_string_arg_exec_target_and_whitespace():
    raw = json.loads(line("process_lsm", "child", 0, policy="r2s-final-shell-block", action="KPROBE_ACTION_OVERRIDE"))
    raw["process_lsm"]["args"] = [{"string_arg": "/bin/sh"}]
    ev = parse_event(json.dumps(raw))
    assert correlate.summarize(ev) == "apache2 → /bin/sh 실행 차단"
    assert correlate.redact('node -e "\n const a = 1;\n"') == 'node -e " const a = 1; "'


def test_redact_secrets():
    assert correlate.redact("curl -u admin:pa55 http://x") == "curl -u <가림> http://x"
    assert "s3cr3t" not in correlate.redact("app --password=s3cr3t token=s3cr3t")


def test_sigma_levels_table_and_fallback(tmp_path):
    p = tmp_path / "sigma.yaml"
    lv = SigmaLevels(str(p))
    assert lv.tetragon("x") == "informational"
    assert lv.falco("r", "Critical") == "critical" and lv.falco("r", "Warning") == "medium"
    p.write_text("tetragon:\n  x: {level: high, sigma: t}\nfalco:\n  r: {level: low}\n", encoding="utf-8")
    assert lv.tetragon("x") == "high" and lv.falco("r", "Critical") == "low"


# ---- 수집기 ----

class FakeLoki(LokiClient):
    def __init__(self, lines: list[str]) -> None:
        # Loki 타임스탬프 = 이벤트 시각 + 1초 (수집 지연)
        self.events = [(parse_time_ns(json.loads(x)["time"]) + NS, x) for x in lines]
        self.calls = []

    async def query_range(self, expr, start_ns, end_ns, limit=5000):
        self.calls.append(expr)
        out = [(t, x) for t, x in self.events if start_ns <= t < end_ns]
        if "KPROBE_ACTION_(SIGKILL|OVERRIDE)" in expr:
            out = [(t, x) for t, x in out if "KPROBE_ACTION_OVERRIDE" in x or "KPROBE_ACTION_SIGKILL" in x]
        elif '|= "' in expr:
            pod = expr.split('|= "')[1].rstrip('"')
            out = [(t, x) for t, x in out if pod in x]
        return sorted(out)[:limit]


@pytest.fixture
async def store(tmp_path):
    s = await IncidentStore.open(str(tmp_path / "inc.db"))
    yield s
    await s.close()


async def _run(settings, store, lines, now_ns):
    c = Collector(settings, store, FakeLoki(lines), SigmaLevels(settings.sigma_levels_file))
    await store.set_state(CURSOR_KEY, str(T0 - 120 * NS))
    while await c.step(now_ns=now_ns):
        pass
    return c


async def test_collector_creates_one_blocked_incident(settings, store):
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    rows = await store.query(_all())
    assert len(rows) == 1
    inc = rows[0]
    assert inc.status == "blocked" and inc.action == "Override" and inc.detected_by == "tetragon"
    assert inc.runtime == "PHP" and inc.runtime_detail == "dvwa:php8.5.11"
    assert inc.summary == "apache2 → /usr/bin/dash 실행 차단"
    assert inc.exec_id == "child" and inc.parent_exec_id == "worker"
    assert inc.member_count == 5 and inc.level == "informational"


async def test_collector_respects_lag_and_is_idempotent(settings, store):
    # 병합 대기 시간이 안 지난 구간은 읽지 않는다
    await _run(settings, store, attack_lines(), now_ns=T0 + 5 * NS)
    assert await store.query(_all()) == []
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)  # 같은 구간 재처리
    rows = await store.query(_all())
    assert len(rows) == 1 and rows[0].member_count == 5


async def test_collector_merges_across_batches(settings, store):
    first = attack_lines()
    later = [line("process_lsm", "child2", 8, **BLOCK)]  # 같은 부모(worker), 8초 뒤
    await _run(settings, store, first, now_ns=T0 + 17 * NS)  # 첫 배치는 기준점 1만 포함
    await _run(settings, store, first + later, now_ns=T0 + 60 * NS)
    rows = await store.query(_all())
    assert len(rows) == 1 and rows[0].last_ms > rows[0].anchor_ms


async def test_collector_ignores_unwatched_namespace(settings, store):
    lines = [line("process_lsm", "child", 0, ns="r2s-e2e", **BLOCK)]
    await _run(settings, store, lines, now_ns=T0 + 60 * NS)
    assert await store.query(_all()) == []


def _all():
    from app.core.params import CommonFilters
    return CommonFilters(0, 2**62, None, None, None)


# ---- Falco ----

def falco_body(dt: float, uuid="u-1", pid=8001, ppid=7277, priority="Critical") -> dict:
    return {
        "uuid": uuid, "rule": "Shell Spawned in Vuln Lab", "priority": priority, "time": _iso(T0 + int(dt * NS)),
        "hostname": "k8s-worker2",
        "output_fields": {"k8s.ns.name": "vuln-lab", "k8s.pod.name": POD, "container.id": CID[:12],
                          "proc.pid": pid, "proc.ppid": ppid, "proc.cmdline": "sh -c id", "fd.rip": "198.51.100.7"},
    }


async def test_falco_before_block_keeps_falco_trace_id(settings, store):
    lv = SigmaLevels(settings.sigma_levels_file)
    r = await ingest_falco(store, lv, settings, falco_body(-0.5))
    assert r["status"] == "pending"
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    rows = await store.query(_all())
    assert len(rows) == 1
    inc = rows[0]
    assert inc.trace_id == r["trace_id"] and inc.status == "blocked" and inc.detected_by == "tetragon+falco"
    assert inc.level == "critical" and inc.level_source == "falco:Shell Spawned in Vuln Lab"
    assert inc.src_ip == "198.51.100.7"


async def test_falco_after_block_attaches(settings, store):
    lv = SigmaLevels(settings.sigma_levels_file)
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    r = await ingest_falco(store, lv, settings, falco_body(3))
    assert r["status"] == "blocked"
    rows = await store.query(_all())
    assert len(rows) == 1 and rows[0].falco_rules == ["Shell Spawned in Vuln Lab"]
    dup = await ingest_falco(store, lv, settings, falco_body(3))
    assert dup["duplicate"] is True


async def test_falco_without_block_becomes_unblocked(settings, store):
    lv = SigmaLevels(settings.sigma_levels_file)
    await ingest_falco(store, lv, settings, falco_body(0, pid=9999, ppid=9998))
    await _run(settings, store, [], now_ns=T0 + 20 * NS)
    assert (await store.query(_all()))[0].status == "pending"
    await _run(settings, store, [], now_ns=T0 + 60 * NS)
    assert (await store.query(_all()))[0].status == "unblocked"


async def test_falco_filters(settings, store):
    lv = SigmaLevels(settings.sigma_levels_file)
    assert (await ingest_falco(store, lv, settings, falco_body(0, priority="Notice")))["ignored"]
    body = falco_body(0)
    body["output_fields"]["k8s.ns.name"] = "kube-system"
    assert (await ingest_falco(store, lv, settings, body))["ignored"]


# ---- API ----

@pytest.fixture
def seeded(app, settings):
    from fastapi.testclient import TestClient

    async def seed():
        s = app.state.incidents
        await _run(settings, s, attack_lines(), now_ns=T0 + 60 * NS)
        await ingest_falco(s, app.state.sigma_levels, settings, falco_body(100, uuid="u-2", pid=1, ppid=2))

    with TestClient(app) as c:
        c.portal.call(seed)  # 앱과 같은 이벤트 루프에서 넣는다
        yield c


def _q(**kw):
    base = {"from": T0 // 1_000_000 - 3_600_000, "to": T0 // 1_000_000 + 3_600_000}
    return {**base, **kw}


@respx.mock(assert_all_mocked=False, assert_all_called=False)
def test_summary_and_queue(seeded, auth, respx_mock):
    respx_mock.route(host="prom.test").mock(
        return_value=httpx.Response(200, json={"data": {"result": [{"value": [0, "4"]}]}})
    )
    respx_mock.route(host="testserver").pass_through()
    s = seeded.get("/incidents/summary", params=_q(namespace="All", runtime="Java,PHP,Node", status="$__all",
                                                   level="critical,high,medium,low,informational"), headers=auth).json()
    assert s["blocked_count"] == 1 and s["unblocked_count"] == 1 and s["unblocked_last_time"]
    assert s["attacked_workloads"] == 1 and s["total_workloads"] == 4
    assert s["level_critical_count"] == 1 and s["level_informational_count"] == 1

    rows = seeded.get("/incidents", params=_q(), headers=auth).json()
    assert [r["status"] for r in rows] == ["pending", "blocked"]  # 미차단(판정 중) 먼저
    r = rows[1]
    assert r["status_text"] == "차단됨 · Override" and r["workload"] == f"vuln-lab / {POD}"
    assert r["window_from_ms"] < r["start_ms"] < r["window_to_ms"] and r["mitre_text"] == "-"

    assert len(seeded.get("/incidents", params=_q(status="pending"), headers=auth).json()) == 1
    assert len(seeded.get("/incidents", params=_q(level="critical"), headers=auth).json()) == 1
    assert seeded.get("/incidents", params=_q(runtime="Java"), headers=auth).json() == []

    one = seeded.get(f"/incidents/{r['trace_id']}", headers=auth).json()
    assert one["exec_id"] == "child" and one["member_count"] == 5


def test_by_workload_timeseries_and_errors(seeded, auth):
    bw = seeded.get("/incidents/by-workload", params=_q(), headers=auth).json()
    assert bw == [{"pod": POD, "blocked": 1, "unblocked": 1, "total": 2, "label": "2건 · 미차단 1"}]

    ts = seeded.get("/incidents/timeseries", params=_q(interval="5m"), headers=auth).json()
    assert len(ts) == 25 and sum(b["blocked"] for b in ts) == 1 and sum(b["unblocked"] for b in ts) == 1

    assert seeded.get("/incidents/" + "0" * 32, headers=auth).status_code == 404
    assert seeded.get("/incidents/nothex", headers=auth).status_code == 400
    assert seeded.get("/incidents", params=_q(level="severe"), headers=auth).status_code == 400
    assert seeded.get("/incidents/timeseries", params=_q(interval="5x"), headers=auth).status_code == 400
    assert seeded.get("/incidents").status_code == 401


def test_falco_webhook_auth(client):
    assert client.post("/ingest/falco", json={}).status_code == 401
    h = {"Authorization": "Bearer falco-token-5678"}
    r = client.post("/ingest/falco", json=falco_body(0), headers=h)
    assert r.status_code == 202 and r.json()["status"] == "pending"
    # Grafana 토큰으로는 받지 않는다
    assert client.post("/ingest/falco", json=falco_body(0), headers={"Authorization": "Bearer test-token-1234"}).status_code == 401


# ---- Tempo·Beyla (2단계) ----

from app.incidents.tempo import BeylaLink, TempoClient


class FakeTempo(TempoClient):
    def __init__(self, link: BeylaLink | None = None) -> None:
        self.link = link
        self.exports: list[list[dict]] = []

    async def find_beyla_span(self, pod, at_ns):
        return self.link

    async def export(self, spans, resource):
        self.exports.append(spans)
        return True


async def _run_t(settings, store, lines, now_ns, tempo):
    c = Collector(settings, store, FakeLoki(lines), SigmaLevels(settings.sigma_levels_file), tempo=tempo)
    await store.set_state(CURSOR_KEY, str(T0 - 120 * NS))
    while await c.step(now_ns=now_ns):
        pass


LINK = BeylaLink("ab" * 16, "cd" * 8, "10.233.66.37", "high")


async def test_trace_spans_layers_and_link(settings, store):
    tempo = FakeTempo(LINK)
    await _run_t(settings, store, attack_lines(), T0 + 60 * NS, tempo)
    inc = (await store.query(_all()))[0]
    assert inc.beyla_trace_id == LINK.trace_id and inc.src_ip == "10.233.66.37"
    spans = tempo.exports[0]
    root = spans[0]
    assert root["traceId"] == inc.trace_id and "parentSpanId" not in root
    assert root["links"][0]["traceId"] == LINK.trace_id and root["status"]["code"] == 2
    layers = {a["value"]["stringValue"] for s in spans[1:] for a in s["attributes"] if a["key"] == "tefal.layer"}
    assert layers == {"proc", "app·uprobe", "kernel·LSM"}
    by_id = {s["spanId"]: s for s in spans}
    # child proc span은 worker proc span 아래, LSM 이벤트는 child proc span 아래
    lsm = [s for s in spans if s["name"].startswith("kernel·LSM")]
    assert lsm and all(s["status"]["code"] == 2 for s in lsm)
    assert by_id[lsm[0]["parentSpanId"]]["name"] == "proc apache2"
    assert len({s["spanId"] for s in spans}) == len(spans)
    # 같은 구간을 다시 처리해도 이미 보낸 span은 다시 보내지 않는다 (중복 span → Trace View 깨짐)
    again = FakeTempo(LINK)
    await _run_t(settings, store, attack_lines(), T0 + 60 * NS, again)
    assert again.exports == []


async def test_same_http_request_merges_beyond_merge_window(settings, store):
    tempo = FakeTempo(LINK)
    later = [line("process_lsm", "child2", 14, **BLOCK)]  # 14초 뒤 (병합 간격 10초 초과)
    PROCS["child2"] = (8050, 60, "other-worker", "/usr/sbin/apache2")  # 다른 부모
    try:
        await _run_t(settings, store, attack_lines() + later, T0 + 60 * NS, tempo)
    finally:
        PROCS["child2"] = (8050, 60, "worker", "/usr/sbin/apache2")
    assert len(await store.query(_all())) == 1


async def test_without_beyla_link_far_attempts_stay_separate(settings, store):
    later = [line("process_lsm", "child2", 14, **BLOCK)]
    PROCS["child2"] = (8050, 60, "other-worker", "/usr/sbin/apache2")
    try:
        await _run_t(settings, store, attack_lines() + later, T0 + 60 * NS, FakeTempo(None))
    finally:
        PROCS["child2"] = (8050, 60, "worker", "/usr/sbin/apache2")
    assert len(await store.query(_all())) == 2


async def test_level_tie_prefers_block_policy(settings, store):
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    inc = (await store.query(_all()))[0]
    assert inc.level_source == "tetragon:php2shell-lsm-bprm-block"


async def test_incident_log_line(settings, store, caplog):
    import logging
    with caplog.at_level(logging.INFO, logger="tefal.incident"):
        await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    inc = (await store.query(_all()))[0]
    assert f"tefal_incident trace_id={inc.trace_id} status=blocked" in caplog.text


@respx.mock
async def test_find_beyla_span_picks_covering_span():
    at = T0
    def sp(sid, start_off, dur):
        return {"spanID": sid, "startTimeUnixNano": str(at + int(start_off * NS)), "durationNanos": str(int(dur * NS)),
                "attributes": [{"key": "client.address", "value": {"stringValue": "10.0.0.9"}}]}
    respx.get("http://tempo.test:3200/api/search").mock(return_value=httpx.Response(200, json={"traces": [
        {"traceID": "1" * 32, "spanSets": [{"spans": [sp("a" * 16, -1, 2)]}]},
        {"traceID": "2" * 30, "spanSets": [{"spans": [sp("b" * 16, -0.5, 3)]}]},
        {"traceID": "3" * 32, "spanSets": [{"spans": [sp("c" * 16, -9, 1)]}]},  # 감싸지 않음
    ]}))
    async with httpx.AsyncClient() as http:
        t = TempoClient(http, "http://tempo.test:3200", "http://tempo.test:4318/v1/traces")
        link = await t.find_beyla_span(POD, at)
        assert link.span_id == "b" * 16 and link.trace_id == "00" + "2" * 30
        assert link.confidence == "low" and link.client_address == "10.0.0.9"
        assert await t.find_beyla_span("Bad Pod", at) is None


async def test_beyla_request_start_clips_lookback(settings, store):
    # uprobe(-0.00006s)는 요청 시작(-0.00003s) 1초 여유 안이라 남고, -2초 probe 같은 이전 이벤트는 빠진다
    early = [line("process_uprobe", "worker", -5, policy="php2shell-uprobe-popen-observe", action="KPROBE_ACTION_POST")]
    link = BeylaLink("ab" * 16, "cd" * 8, None, "high", T0 - 30_000)
    await _run_t(settings, store, early + attack_lines(), T0 + 60 * NS, FakeTempo(link))
    inc = (await store.query(_all()))[0]
    assert inc.member_count == 5 and inc.start_ms > (T0 - 2 * NS) // 1_000_000



async def test_merge_sends_only_new_spans_once(settings, store):
    tempo = FakeTempo(LINK)
    later = [line("process_lsm", "child2", 8, **BLOCK)]
    await _run_t(settings, store, attack_lines(), T0 + 17 * NS, tempo)
    await _run_t(settings, store, attack_lines() + later, T0 + 60 * NS, tempo)
    sent = [sp["spanId"] for batch in tempo.exports for sp in batch]
    assert len(sent) == len(set(sent))  # 루트 포함 어떤 span도 두 번 가지 않는다
    roots = [sp for batch in tempo.exports for sp in batch if "parentSpanId" not in sp]
    assert len(roots) == 1 and len(tempo.exports) == 2


@respx.mock
async def test_find_beyla_span_tolerance():
    def resp(start_off, dur):
        return httpx.Response(200, json={"traces": [{"traceID": "1" * 32, "spanSets": [{"spans": [
            {"spanID": "a" * 16, "startTimeUnixNano": str(T0 + int(start_off * NS)), "durationNanos": str(int(dur * NS))}]}]}]})
    async with httpx.AsyncClient() as http:
        t = TempoClient(http, "http://tempo.test:3200", "http://tempo.test:4318/v1/traces")
        route = respx.get("http://tempo.test:3200/api/search")
        route.mock(return_value=resp(0.003, 0.2))  # 요청이 기준점보다 3ms 늦게 시작 (실제 사례)
        assert (await t.find_beyla_span(POD, T0)).span_id == "a" * 16
        route.mock(return_value=resp(0.8, 0.2))  # 0.8초 뒤: 여유 밖
        assert await t.find_beyla_span(POD, T0) is None
