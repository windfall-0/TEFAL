"""① 계층별 방어 흐름 패널 HTML (Business Text 패널이 그대로 넣는다).

모양은 목업(mockups/flow, 2026-11-05 확정)을 따른다. 스타일과 애니메이션은 대시보드 패널의 CSS(.tf-*)에 있고,
여기서는 구조와 상태 클래스만 만든다. 데이터의 이름(정책·룰·pod)은 모두 이스케이프한다.
"""

from html import escape
from urllib.parse import urlencode

from app import flow
from app.core.timefmt import fmt_hm, fmt_hms, fmt_md

OVERVIEW = "/d/tefal-overview"
INCIDENT = "/d/tefal-incident"
WINDOW_MS = 5 * 60 * 1000
LAYER_COLS = (("app", "lv1"), ("proc", "lv2"), ("lsm", "lv3"))
FEED_LIMIT = 5


def range_text(from_ms: int, to_ms: int, now_ms: int, tz: str) -> str:
    """대시보드 시간 범위 표시: 지금까지면 '최근 N시간', 아니면 'MM/DD HH:MM ~ MM/DD HH:MM'."""
    if now_ms - to_ms < 60_000:
        sec = max(60, (to_ms - from_ms) // 1000)
        for unit, size in (("일", 86400), ("시간", 3600)):
            if sec >= size and sec % size < 60:
                return f"최근 {sec // size}{unit}"
        return f"최근 {round(sec / 60)}분"
    return f"{fmt_md(from_ms, tz)} {fmt_hm(from_ms, tz)} ~ {fmt_md(to_ms, tz)} {fmt_hm(to_ms, tz)}"


def link_range(from_ms: int, to_ms: int, now_ms: int) -> dict:
    """패널 링크의 시간 범위. 지금까지 보는 중이면 상대 범위(now-Ns ~ now)로 넘겨 이동한 화면도 계속 갱신되게 한다."""
    if now_ms - to_ms < 60_000:
        sec = max(60, (to_ms - from_ms) // 1000)
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if sec % size == 0:  # 시간 선택기에 'Last 24 hours'처럼 보이게
                return {"from": f"now-{sec // size}{unit}", "to": "now"}
        return {"from": f"now-{sec}s", "to": "now"}
    return {"from": from_ms, "to": to_ms}


def _href(path: str, **params) -> str:
    return escape(path + "?" + urlencode({k: v for k, v in params.items() if v is not None}))


def _arrow(on: bool) -> str:
    return f'<span class="tf-arrow{" on" if on else ""}" aria-hidden="true"></span>'


def _cell(value, policy: str | None, level: str, recent: bool) -> str:
    if value is None:
        return '<span class="tf-cell none"><b>-</b><small>해당 없음</small></span>'
    cls = level if value else "zero"
    return (f'<span class="tf-cell {cls}{" recent" if recent and value else ""}">'
            f"<b>{value}</b><small>{escape(policy or '')}</small></span>")


def _row(r: dict, tr: dict) -> str:
    rt = r["runtime"]
    out = [f'<a class="tf-grid tf-row" href="{_href(OVERVIEW, **tr, **{"var-runtime": rt})}">',
           f'<span class="tf-name">{escape(rt)}</span>',
           f'<span class="tf-inc">{r["incidents"]}</span>']
    prev = r["incidents"]
    for key, level in LAYER_COLS:
        v = r.get(key)
        out.append(_arrow(bool(prev) and bool(v)))
        out.append(_cell(v, r["policy"].get(key), level, bool((r["recent"] or {}).get(key))))
        prev = v
    out.append('<span class="tf-wall" aria-hidden="true"></span>')
    out.append(f'<span class="tf-result"><b>차단 {r["blocked"]}</b><small>미차단 {r["unblocked"]}</small></span>')
    out.append("</a>")
    return "".join(out)


def _feed_item(inc, tz: str, first: bool) -> str:
    key = "Falco" if flow.row_key(inc) == flow.FALCO_ONLY else (inc.runtime or "기타")
    if key == "Falco":
        path = escape(inc.falco_rules[0] if inc.falco_rules else "Falco 경보")
    else:
        steps = []
        for layer in ("app", "proc"):
            if layer in inc.layers:
                steps.append(escape(flow.short_policy(inc.layer_policies.get(layer)) or layer))
        if "lsm" in inc.layers:
            steps.append("<b>LSM 차단</b>")
        elif inc.status == "blocked":  # LSM이 아닌 곳에서 막힘 (예: kprobe Sigkill)
            steps.append("<b>강제 종료</b>" if inc.action == "Sigkill" else "<b>차단</b>")
        path = " → ".join(steps) or escape(inc.summary[:40])
    blocked = inc.status == "blocked"
    href = _href(INCIDENT, **{"var-trace_id": inc.trace_id, "from": inc.start_ms - WINDOW_MS,
                              "to": max(inc.anchor_ms, inc.last_ms) + WINDOW_MS})
    return (f'<a class="tf-item{" new" if first else ""}" href="{href}">'
            f'<span class="tf-time">{fmt_hms(inc.start_ms, tz)}</span>'
            f'<span class="tf-svc{" falco" if key == "Falco" else ""}">{escape(key)}</span>'
            f'<span class="tf-path">{path}</span>'
            f'<span class="tf-badge{"" if blocked else " bad"}">{"차단" if blocked else "미차단"}</span></a>')


def render(rows: list[dict], feed: list, last_block_text: str, rng: str, tr: dict, tz: str, live: bool,
           now_ms: int = 0) -> str:
    tet = [r for r in rows if r["runtime"] in flow.RUNTIMES]
    fal = next((r for r in rows if r["runtime"] == flow.FALCO_ONLY), None)
    head = ('<div class="tf-head"><div class="tf-title"><b>계층별 방어 흐름</b>'
            f"<span>사건 기준 · {escape(rng)}</span></div><div class=\"tf-meta\">"
            + ('<span class="tf-live"><i></i>LIVE</span>' if live else "")
            + f'<span class="tf-last">{escape(last_block_text)}</span></div></div>')
    colhead = ('<div class="tf-grid tf-colhead"><span>서비스</span><span>사건</span><span></span>'
               "<span>앱 탐지 · uprobe</span><span></span><span>프로세스 · kprobe</span><span></span>"
               "<span>커널 차단 · LSM</span><span></span><span>결과</span></div>")
    tet_box = ('<div class="tf-box tet"><span class="tf-tag">Tetragon · eBPF 차단 경로</span>'
               + "".join(_row(r, tr) for r in tet) + "</div>")
    fal_box = ""
    if fal is not None:
        fal_box = ('<div class="tf-box fal"><span class="tf-tag">Falco · 탐지 전용</span>'
                   f'<a class="tf-falrow" href="{_href(OVERVIEW, **tr, **{"var-status": "unblocked"})}">'
                   f'<span class="tf-name">{escape(fal["runtime"])}</span><span class="tf-inc">{fal["incidents"]}</span>'
                   '<span class="tf-dash"><i></i>커널 차단 없이 탐지만<i></i></span>'
                   f'<span class="tf-unblocked{" zero" if not fal["unblocked"] else ""}">미차단 {fal["unblocked"]}</span>'
                   "</a></div>")
    # 패널은 5초마다 다시 그려지므로 '새 줄' 애니메이션은 맨 위 사건이 최근 5분 안일 때만 붙인다
    items = "".join(_feed_item(inc, tz, i == 0 and now_ms - inc.start_ms <= WINDOW_MS)
                    for i, inc in enumerate(feed[:FEED_LIMIT]))
    items = items or '<span class="tf-empty">이 시간 범위에 사건이 없습니다</span>'
    feed_box = ('<div class="tf-feed"><div class="tf-feedhead"><span>최근 공격</span>'
                f'<a href="{_href(OVERVIEW, **tr)}">사건 큐 전체 보기</a></div>{items}</div>')
    return (f'<div class="tf">{head}<div class="tf-body"><div class="tf-left">{colhead}{tet_box}{fal_box}</div>'
            f"{feed_box}</div></div>")
