"""Tempo 연동 (4.3 4번, 4.6): Beyla HTTP span 찾기와 사건 trace 기록(OTLP/HTTP JSON).

- span ID는 (trace_id, 종류, 키)의 해시라서 같은 사건을 다시 보내도 같은 span이 된다.
  Tempo는 조회 시 같은 span ID를 하나로 합친다.
- 기록 실패는 사건 생성을 막지 않는다(메트릭과 로그만 남긴다).
"""

import hashlib
import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

import httpx
from prometheus_client import Counter

from app.incidents.tetragon import TetragonEvent

log = logging.getLogger(__name__)
NS = 1_000_000_000

TEMPO_EXPORTS = Counter("tefal_tempo_exports_total", "사건 trace 기록", ["outcome"])  # ok | error
BEYLA_LOOKUPS = Counter("tefal_beyla_lookups_total", "Beyla span 연결", ["result"])  # high | low | none | error

BEYLA_TOLERANCE_NS = 500_000_000  # ±0.5초
_POD_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
LAYER = {
    "process_uprobe": "app·uprobe",
    "process_exec": "proc",
    "process_exit": "proc",
    "process_kprobe": "proc",
    "process_lsm": "kernel·LSM",
}


def span_id(trace_id: str, *parts: object) -> str:
    h = hashlib.sha256("|".join([trace_id, *map(str, parts)]).encode()).hexdigest()[:16]
    return h[:15] + "1" if h == "0" * 16 else h


@dataclass(frozen=True)
class BeylaLink:
    trace_id: str
    span_id: str
    client_address: str | None
    confidence: str  # high | low
    start_ns: int | None = None  # HTTP 요청 시작 (역조회 하한)


def link_of(inc) -> "BeylaLink | None":
    """사건에 저장된 Beyla 연결 (root span을 다시 보내도 같은 link가 붙게)."""
    if not (inc.beyla_trace_id and inc.beyla_span_id):
        return None
    return BeylaLink(inc.beyla_trace_id, inc.beyla_span_id, inc.src_ip, inc.beyla_link_confidence or "low")


def _attr_value(v: dict):
    return next(iter(v.values()), None) if isinstance(v, dict) else v


def _attrs(d: dict) -> list[dict]:
    out = []
    for k, v in d.items():
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, bool):
            out.append({"key": k, "value": {"boolValue": v}})
        elif isinstance(v, int):
            out.append({"key": k, "value": {"intValue": str(v)}})
        else:
            out.append({"key": k, "value": {"stringValue": str(v)}})
    return out


class TempoClient:
    def __init__(self, http: httpx.AsyncClient, query_url: str, otlp_url: str) -> None:
        self._http = http
        self._query = query_url.rstrip("/")
        self._otlp = otlp_url

    async def find_beyla_span(self, pod: str, at_ns: int) -> BeylaLink | None:
        """같은 pod에서 at_ns를 시작~끝 사이에 포함하는 HTTP server span (4.3 4번)."""
        if not _POD_RE.fullmatch(pod):
            return None
        q = f'{{ resource.k8s.pod.name = "{pod}" && kind = server }} | select(span.client.address)'
        try:
            r = await self._http.get(
                f"{self._query}/api/search",
                # 범위를 넓히면 요청이 많은 앱(php 공격 시 초당 여러 건)에서 결과 한도에 걸려 맞는 span이 잘린다.
                # 기준점을 감싸는 요청은 기준점 직전에 시작하므로 60초 전 ~ 2초 후면 충분하다.
                params={"q": q, "start": at_ns // NS - 60, "end": at_ns // NS + 2, "limit": 500, "spss": 50},
                timeout=15.0,
            )
            r.raise_for_status()
            traces = r.json().get("traces") or []
        except (httpx.HTTPError, ValueError) as e:
            BEYLA_LOOKUPS.labels("error").inc()
            log.warning("Beyla span 조회 실패: %s", type(e).__name__)
            return None
        # Beyla와 Tetragon 시각은 수 ms 어긋날 수 있어 span 앞뒤로 여유를 둔다
        tol = BEYLA_TOLERANCE_NS
        cands = []  # (span 밖으로 벗어난 거리, -시작 시각, ...) → 감싸는 것 우선, 그다음 가까운 것
        for t in traces:
            for ss in t.get("spanSets") or ([t["spanSet"]] if t.get("spanSet") else []):
                for sp in ss.get("spans") or []:
                    s0 = int(sp.get("startTimeUnixNano", 0))
                    s1 = s0 + int(sp.get("durationNanos", 0))
                    if s0 - tol <= at_ns <= s1 + tol:
                        gap = max(0, s0 - at_ns, at_ns - s1)
                        attrs = {a["key"]: _attr_value(a.get("value")) for a in sp.get("attributes") or []}
                        cands.append((gap, -s0, t["traceID"].rjust(32, "0"), sp["spanID"], attrs.get("client.address")))
        if not cands:
            BEYLA_LOOKUPS.labels("none").inc()
            return None
        # 후보가 여럿이면(Java·Node 동시 요청 등) 감싸는 것 중 시작이 가장 늦은 것
        gap, neg_s0, tid, sid, client = min(cands)
        conf = "high" if len({c[3] for c in cands}) == 1 else "low"
        BEYLA_LOOKUPS.labels(conf).inc()
        return BeylaLink(tid, sid, client, conf, -neg_s0)

    async def export(self, spans: list[dict], resource: dict) -> bool:
        body = {
            "resourceSpans": [
                {
                    "resource": {"attributes": _attrs(resource)},
                    "scopeSpans": [{"scope": {"name": "tefal-backend"}, "spans": spans}],
                }
            ]
        }
        try:
            r = await self._http.post(self._otlp, json=body, timeout=15.0)
            r.raise_for_status()
        except httpx.HTTPError as e:
            TEMPO_EXPORTS.labels("error").inc()
            log.warning("Tempo 기록 실패: %s", type(e).__name__)
            return False
        TEMPO_EXPORTS.labels("ok").inc()
        return True


# ---- span 만들기 ----


def _span(trace_id, sid, parent, name, start_ns, end_ns, attrs, *, error=False, links=None) -> dict:
    sp = {
        "traceId": trace_id,
        "spanId": sid,
        "name": name,
        "kind": 1,  # INTERNAL
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(max(end_ns, start_ns + 1000)),
        "attributes": _attrs(attrs),
        "status": {"code": 2, "message": "blocked"} if error else {"code": 0},
    }
    if parent:
        sp["parentSpanId"] = parent
    if links:
        sp["links"] = links
    return sp


def root_span(inc, start_ns: int, end_ns: int, beyla: BeylaLink | None) -> dict:
    """사건 전체를 감싸는 span. span ID는 trace_id만으로 정해진다."""
    links = None
    if beyla:
        links = [{
            "traceId": beyla.trace_id,
            "spanId": beyla.span_id,
            "attributes": _attrs({"tefal.link": "beyla_http", "tefal.link_confidence": beyla.confidence}),
        }]
    return _span(
        inc.trace_id, span_id(inc.trace_id, "root"), None, f"incident {inc.pod}", start_ns, end_ns,
        {
            "k8s.namespace": inc.namespace, "k8s.pod": inc.pod, "tefal.runtime": inc.runtime,
            "tefal.action": inc.action, "tefal.policy": inc.policy, "tefal.summary": inc.summary,
            "tefal.mitre": ",".join(inc.mitre), "tefal.status": inc.status, "tefal.level": inc.level,
            "net.src_ip": inc.src_ip, "tetragon.exec_id": inc.exec_id,
            "tetragon.parent_exec_id": inc.parent_exec_id,
            "tefal.link_confidence": beyla.confidence if beyla else None,
        },
        error=inc.status == "blocked",
        links=links,
    )


def tetragon_spans(trace_id: str, root: str, events: Iterable[TetragonEvent], redact) -> list[dict]:
    """프로세스마다 proc span(exec~exit), 그 아래 uprobe/kprobe/LSM 이벤트 span."""
    events = sorted(events, key=lambda e: e.time_ns)
    procs: dict[str, dict] = {}
    for e in events:
        p = procs.setdefault(e.process.exec_id, {"ev": e, "start": e.time_ns, "end": e.time_ns})
        p["start"], p["end"] = min(p["start"], e.time_ns), max(p["end"], e.time_ns)
    out = []
    for eid, p in procs.items():
        e: TetragonEvent = p["ev"]
        parent_eid = e.process.parent_exec_id
        parent = span_id(trace_id, "proc", parent_eid) if parent_eid in procs else root
        out.append(_span(
            trace_id, span_id(trace_id, "proc", eid), parent,
            f"proc {os.path.basename(e.process.binary)}", p["start"], p["end"],
            {"tefal.layer": "proc", "process.pid": e.process.pid,
             "process.binary": e.process.binary, "process.args": redact(e.process.arguments)[:500],
             "tetragon.exec_id": eid, "tetragon.parent_exec_id": parent_eid, "k8s.pod": e.pod},
        ))
    for e in events:
        if e.event_type in ("process_exec", "process_exit"):
            continue  # proc span 시작·끝으로 표현
        layer = LAYER.get(e.event_type, "proc")
        what = e.function or e.policy or e.event_type.removeprefix("process_")
        out.append(_span(
            trace_id, span_id(trace_id, "ev", e.process.exec_id, e.time_ns, e.event_type),
            span_id(trace_id, "proc", e.process.exec_id),
            f"{layer} {what}", e.time_ns, e.time_ns,
            {"tefal.layer": layer, "tefal.policy": e.policy,
             "tefal.action": (e.action or "").removeprefix("KPROBE_ACTION_").title() or None,
             "tetragon.event": e.event_type, "tetragon.target": e.file_arg,
             "tetragon.exec_id": e.process.exec_id, "process.pid": e.process.pid},
            error=e.is_anchor,
        ))
    return out


def falco_span(trace_id: str, root: str, uuid: str, t_ns: int, rule: str, priority: str, output_fields: dict, redact) -> dict:
    return _span(
        trace_id, span_id(trace_id, "falco", uuid), root, f"falco {rule}", t_ns, t_ns,
        {"tefal.layer": "falco", "falco.rule": rule, "falco.priority": priority, "falco.uuid": uuid,
         "process.pid": output_fields.get("proc.pid"),
         "process.cmdline": redact(str(output_fields.get("proc.cmdline") or ""))[:500],
         "net.src_ip": output_fields.get("fd.rip")},
    )


RESOURCE = {"service.name": "tefal-incident", "service.namespace": "tefal"}


async def export_new(tempo: "TempoClient | None", store, trace_id: str, spans: list[dict]) -> None:
    """아직 보내지 않은 span만 보낸다. 루트 span도 처음 한 번만 간다(다시 보내면 Trace View가 깨진다)."""
    if tempo is None:
        return
    new = await store.unsent_spans(trace_id, spans)
    if new and await tempo.export(new, RESOURCE):
        await store.mark_exported(trace_id, new)
