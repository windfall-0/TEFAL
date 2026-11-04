"""묶인 기준점 → 사건 레코드 저장 (4.4 병합 규칙 포함), Tempo·Loki 기록 (4.6)."""

import logging

from app.config import Settings
from app.incidents import correlate
from app.incidents.levels import SigmaLevels, highest
from app.incidents.store import Incident, IncidentStore, Member
from app.incidents.tempo import (
    TempoClient,
    export_new,
    link_of,
    root_span,
    tetragon_spans,
)
from app.incidents.tetragon import TetragonEvent

MS = 1_000_000
# 사건 요약 1줄. stdout → Alloy → Loki {namespace="monitoring", container="tefal-backend"}
incident_log = logging.getLogger("tefal.incident")


def log_incident(inc: Incident) -> None:
    """Grafana Loki 데이터소스의 derived field가 trace_id를 Tempo 링크로 바꾼다."""
    incident_log.info(
        "tefal_incident trace_id=%s status=%s level=%s pod=%s policy=%s",
        inc.trace_id, inc.status, inc.level, inc.pod, inc.policy or "-",
    )


def _members(evs: list[TetragonEvent]) -> list[Member]:
    return [Member(e.process.exec_id, e.time_ns, e.event_type, e.process.pid) for e in evs]


def _image_short(image: str) -> str | None:
    return image.rsplit("/", 1)[-1] or None


async def save_cluster(
    store: IncidentStore,
    levels: SigmaLevels,
    settings: Settings,
    cluster: correlate.AnchorCluster,
    window: list[TetragonEvent],
    tempo: TempoClient | None = None,
) -> tuple[str, bool]:
    """사건을 만들거나 기존 사건에 합친다. (trace_id, 새로 만들었는지)"""
    first, last = cluster.first, cluster.last
    beyla = await tempo.find_beyla_span(first.pod, first.time_ns) if tempo else None
    ids = correlate.lineage(cluster, window, settings.correlate_max_depth)
    mem = correlate.members(
        cluster, window, ids, settings.correlate_lookback_sec, beyla.start_ns if beyla else None
    )
    first_ms, last_ms = first.time_ns // MS, last.time_ns // MS
    wait_ms = settings.falco_wait_sec * 1000
    pids = {e.process.pid for e in mem if e.process.pid is not None}

    existing = await store.find_mergeable(
        cluster.node, cluster.parent_exec_id, first_ms - settings.correlate_merge_sec * 1000
    )
    if existing is None and beyla is not None:
        # 같은 HTTP 요청 안의 연속 시도는 병합 간격을 넘어도 한 사건이다
        existing = await store.find_by_beyla(beyla.trace_id, first.pod)
    falco = await store.find_by_lineage(
        first.container_id, pids, first_ms - wait_ms, last_ms + wait_ms, falco_only=True
    )

    created = False
    if existing is not None:
        inc = existing
        if falco is not None:  # Falco로 먼저 만든 사건이 있으면 기존 Tetragon 사건으로 흡수
            await store.move_members(falco.trace_id, inc.trace_id)
            inc.falco_rules = sorted({*inc.falco_rules, *falco.falco_rules})
            inc.src_ip = inc.src_ip or falco.src_ip
            times = [t for t in (inc.falco_ms, falco.falco_ms) if t is not None]
            inc.falco_ms = min(times) if times else None
            inc.level, inc.level_source = highest([(inc.level, inc.level_source), (falco.level, falco.level_source)])
    elif falco is not None:
        # Falco 선행 경보: 먼저 만든 trace_id를 유지하고 차단으로 바꾼다
        inc = falco
        inc.anchor_ms = first_ms
        inc.summary = correlate.summarize(first)
        inc.exec_id, inc.parent_exec_id = first.process.exec_id, cluster.parent_exec_id
        inc.policy = first.policy
        inc.container_id = first.container_id
    else:
        created = True
        inc = Incident(
            trace_id=correlate.make_trace_id(first.node, first.process.exec_id, first.time_ns),
            start_ms=first_ms,
            anchor_ms=first_ms,
            last_ms=last_ms,
            status="blocked",
            level="informational",
            level_source=None,
            action="Override",
            detected_by="tetragon",
            namespace=first.namespace,
            pod=first.pod,
            node=first.node,
            runtime=None,
            runtime_detail=None,
            summary=correlate.summarize(first),
            exec_id=first.process.exec_id,
            parent_exec_id=cluster.parent_exec_id,
            policy=first.policy,
            container_id=first.container_id,
        )

    inc.status = "blocked"
    inc.start_ms = min(inc.start_ms, mem[0].time_ns // MS if mem else first_ms)
    inc.last_ms = max(inc.last_ms, last_ms)
    if inc.action != "Sigkill":
        inc.action = correlate.action_label(cluster.anchors)
    inc.detected_by = "tetragon+falco" if inc.falco_rules else "tetragon"

    # 단계가 같으면 앞에 있는 것이 이긴다: 차단 정책 → 기존 값 → 관찰 정책 순
    anchor_policies = sorted({a.policy for a in cluster.anchors if a.policy})
    cands = [(levels.tetragon(p), f"tetragon:{p}") for p in anchor_policies]
    if inc.level_source:
        cands.append((inc.level, inc.level_source))
    for p in sorted({e.policy for e in mem if e.policy} - set(anchor_policies)):
        cands.append((levels.tetragon(p), f"tetragon:{p}"))
    if cands:
        inc.level, inc.level_source = highest(cands)

    binaries = [e.process.binary for e in mem] + [e.parent.binary for e in mem if e.parent]
    binaries += [e.parent.binary for e in window if e.parent and e.process.exec_id in ids]
    inc.runtime = inc.runtime or correlate.detect_runtime(binaries)
    inc.runtime_detail = inc.runtime_detail or _image_short(first.image)

    if beyla is not None and inc.beyla_trace_id is None:
        inc.beyla_trace_id, inc.beyla_span_id = beyla.trace_id, beyla.span_id
        inc.beyla_link_confidence = beyla.confidence
        # 출발지: Beyla client.address 우선, 없으면 Falco fd.rip (4.7)
        inc.src_ip = beyla.client_address or inc.src_ip
    # 사건에 처음 연결된 요청을 유지한다 (root span을 다시 보내도 같은 link)
    link = link_of(inc)

    await store.save(inc)
    await store.add_members(inc.trace_id, _members(mem))
    log_incident(inc)

    if tempo is not None:
        start_ns = min([inc.start_ms * MS, *(e.time_ns for e in mem)])
        end_ns = max([inc.last_ms * MS, *(e.time_ns for e in mem)])
        root = root_span(inc, start_ns, end_ns, link)
        spans = [root, *tetragon_spans(inc.trace_id, root["spanId"], mem, correlate.redact,
                                            int(settings.dedup_gap_sec * 1e9))]
        await export_new(tempo, store, inc.trace_id, spans)
    return inc.trace_id, created

