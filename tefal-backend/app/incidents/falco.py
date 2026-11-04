"""Falcosidekick webhook 경보 처리 (4.2, 4.4)."""

import time

from app.config import Settings
from app.incidents import correlate
from app.incidents.builder import log_incident
from app.incidents.levels import SigmaLevels, falco_priority_rank, highest
from app.incidents.store import Incident, IncidentStore, Member
from app.incidents.tempo import TempoClient, export_new, falco_span, link_of, root_span
from app.incidents.tetragon import parse_time_ns


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


async def ingest_falco(
    store: IncidentStore, levels: SigmaLevels, settings: Settings, body: dict, tempo: TempoClient | None = None
) -> dict:
    uuid = str(body.get("uuid") or "").strip()
    rule = str(body.get("rule") or "").strip()
    priority = str(body.get("priority") or "")
    of = body.get("output_fields") or {}
    if not uuid or not rule or not isinstance(of, dict):
        return {"ignored": True, "reason": "uuid, rule, output_fields가 필요합니다"}

    ns = of.get("k8s.ns.name")
    if ns not in settings.watch_namespace_list:
        return {"ignored": True}
    if falco_priority_rank(priority) < falco_priority_rank(settings.falco_min_priority):
        return {"ignored": True}

    seen = await store.falco_seen(uuid)
    if seen is not None:  # Falcosidekick 재전송
        inc = await store.get(seen)
        return {"trace_id": seen, "status": inc.status if inc else "pending", "duplicate": True}

    t_ns = parse_time_ns(str(body.get("time") or "")) or time.time_ns()
    t_ms = t_ns // 1_000_000
    wait_ms = settings.falco_wait_sec * 1000
    container = str(of.get("container.id") or "")
    pid, ppid = _int(of.get("proc.pid")), _int(of.get("proc.ppid"))
    pids = {p for p in (pid, ppid) if p is not None}
    level = levels.falco(rule, priority)
    src_ip = of.get("fd.rip") or None
    falco_members = [Member(f"falco:{uuid}", t_ns, "falco", pid)]
    if ppid is not None:
        falco_members.append(Member(f"falco:{uuid}", t_ns, "falco_ppid", ppid))

    # 이미 처리한 차단 사건(후행 경보), 또는 같은 계보의 판정 중 사건에 붙인다
    inc = await store.find_by_lineage(container, pids, t_ms - wait_ms, t_ms + wait_ms, falco_only=False)
    inc = inc or await store.find_by_lineage(container, pids, t_ms - wait_ms, t_ms + wait_ms, falco_only=True)
    if inc is not None:
        inc.falco_rules = sorted({*inc.falco_rules, rule})
        inc.src_ip = inc.src_ip or src_ip
        inc.falco_ms = min(inc.falco_ms, t_ms) if inc.falco_ms else t_ms
        inc.level, inc.level_source = highest([(inc.level, inc.level_source), (level, f"falco:{rule}")])
        if inc.detected_by != "falco":
            inc.detected_by = "tetragon+falco"
        inc.start_ms = min(inc.start_ms, t_ms)
        inc.last_ms = max(inc.last_ms, t_ms)
    else:
        node = str(body.get("hostname") or of.get("k8s.node.name") or "")
        cmd = of.get("proc.cmdline") or of.get("proc.exepath") or rule
        inc = Incident(
            trace_id=correlate.make_trace_id(node, uuid, t_ns),
            start_ms=t_ms,
            anchor_ms=t_ms,
            last_ms=t_ms,
            status="pending",
            level=level,
            level_source=f"falco:{rule}",
            action="Detected",
            detected_by="falco",
            namespace=ns,
            pod=str(of.get("k8s.pod.name") or ""),
            node=node,
            runtime=correlate.detect_runtime([str(of.get("proc.pexepath") or ""), str(of.get("proc.exepath") or "")]),
            runtime_detail=(str(of.get("container.image.repository") or "").rsplit("/", 1)[-1] or None),
            summary=correlate.redact(f"{rule}: {str(cmd)[:200]}"),
            src_ip=src_ip,
            container_id=container,
            falco_rules=[rule],
            falco_ms=t_ms,
        )

    await store.save(inc)
    await store.add_members(inc.trace_id, falco_members)
    await store.record_falco(uuid, inc.trace_id)
    await store.commit()
    log_incident(inc)

    if tempo is not None:
        link = link_of(inc)
        root = root_span(inc, inc.start_ms * 1_000_000, max(inc.last_ms * 1_000_000, t_ns), link)
        spans = [root, falco_span(inc.trace_id, root["spanId"], uuid, t_ns, rule, priority, of, correlate.redact)]
        await export_new(tempo, store, inc.trace_id, spans)
        await store.commit()
    return {"trace_id": inc.trace_id, "status": inc.status}
