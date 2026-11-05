import json, sys, os, itertools

OUT = sys.argv[1]

DS_B = {"type": "yesoreyeram-infinity-datasource", "uid": "tefal-backend"}
DS_P = {"type": "prometheus", "uid": "prometheus"}
# 실제 환경(192.168.0.200) Grafana에 이미 있는 데이터소스 UID
DS_L = {"type": "loki", "uid": "P8E80F9AEF21F6940"}
DS_T = {"type": "tempo", "uid": "tempo-ds"}

BLUE, RED, ORANGE, GREEN, GREY = "#5794F2", "#FF7383", "#FFB357", "#73BF69", "#8E8E8E"

NODES = ("k8s-master", "k8s-worker1", "k8s-worker2")  # 192.168.0.200 클러스터 (노드 리소스 막대 순서)

UIDS = {
    "overview": "tefal-overview",
    "incident": "tefal-incident",
    "ti": "tefal-ti",
    "infra": "tefal-infra",
}

TR = "from=${__from}&to=${__to}"
INC_Q = TR + "&namespace=${namespace}&runtime=${runtime:csv}&status=${status}&level=${level:csv}"


# ---------- helpers ----------
def inf(url, cols, ref="A", root=""):
    return {
        "refId": ref, "datasource": DS_B,
        "type": "json", "source": "url", "parser": "backend", "format": "table",
        "url": url, "url_options": {"method": "GET", "data": ""},
        "root_selector": root,
        "columns": [{"selector": s, "text": t, "type": ty} for s, t, ty in cols],
        "filters": [],
    }


def prom(expr, legend, ref="A", instant=True):
    return {"refId": ref, "datasource": DS_P, "expr": expr, "legendFormat": legend,
            "instant": instant, "range": not instant}


def ov(name, **props):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": k.replace("__", "."), "value": v} for k, v in props.items()]}


def hide(name):
    return ov(name, custom__hidden=True)


def fixed(color):
    return {"mode": "fixed", "fixedColor": color}


def thresholds(*steps):
    return {"mode": "absolute",
            "steps": [{"color": c, "value": v} for v, c in steps]}


class Builder:
    def __init__(self):
        self.ids = itertools.count(1)
        self.panels = []

    def add(self, type_, title, x, y, w, h, targets, ds, options=None, defaults=None,
            overrides=None, desc="", links=None, transformations=None):
        p = {
            "id": next(self.ids), "type": type_, "title": title, "description": desc,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "datasource": ds, "targets": targets,
            "options": options or {},
            "fieldConfig": {"defaults": defaults or {}, "overrides": overrides or []},
        }
        if links:
            p["links"] = links
        cols = (targets[0].get("columns") if targets else None) or []
        if type_ == "table" and cols and not transformations:
            # Infinity 표는 열 순서가 정의와 다르게(거꾸로) 나와서 열 순서를 고정한다
            transformations = [{"id": "organize", "options": {
                "indexByName": {c["text"]: i for i, c in enumerate(cols)}}}]
        if transformations:
            p["transformations"] = transformations
        self.panels.append(p)
        return p


def stat_opts(fields="", text="value_and_name", color="value", size=None, orient="auto"):
    o = {
        "reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": fields},
        "textMode": text, "colorMode": color, "graphMode": "none",
        "justifyMode": "auto", "orientation": orient, "wideLayout": True,
        "showPercentChange": False,
    }
    if size:
        o["text"] = {"titleSize": size[0], "valueSize": size[1]}
    return o


def table_opts(sort=None):
    o = {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}
    if sort:
        o["sortBy"] = sort
    return o


def nav_links():
    links = []
    for title, key in [("운영 현황", "overview"), ("사건 상세", "incident"),
                       ("위협 인텔리전스", "ti"), ("인프라", "infra")]:
        incident = key == "incident"  # 사건 상세는 최근 24시간으로 열고, 드롭다운이 가장 최근 사건을 고른다
        links.append({"title": title, "type": "link",
                      "url": "/d/" + UIDS[key] + ("?from=now-24h&to=now" if incident else ""),
                      "icon": "dashboard", "keepTime": not incident, "includeVars": False,
                      "targetBlank": False, "asDropdown": False, "tags": [], "tooltip": ""})
    for title, var in [("Hubble UI", "hubble_url"), ("Headlamp", "headlamp_url")]:
        links.append({"title": title, "type": "link", "url": "${" + var + "}",
                      "icon": "external link", "keepTime": False, "includeVars": False,
                      "targetBlank": True, "asDropdown": False, "tags": [], "tooltip": ""})
    return links


def const(name, value, label=None):
    return {"type": "constant", "name": name, "label": label or name, "hide": 2,
            "query": value, "current": {"text": value, "value": value}, "options": []}


def textbox(name, label, default=""):
    return {"type": "textbox", "name": name, "label": label, "hide": 0, "query": default,
            "current": {"text": default, "value": default}, "options": []}


def custom(name, label, query, multi=False, include_all=True, default_all=True):
    v = {"type": "custom", "name": name, "label": label, "hide": 0, "query": query,
         "multi": multi, "includeAll": include_all, "options": []}
    if include_all:
        v["allValue"] = "All"
    if default_all:
        v["current"] = {"text": ["All"] if multi else "All",
                        "value": ["$__all"] if multi else "$__all"}
    return v


def incident_picker():
    """② 사건 선택. 최근 사건 목록(/incidents/recent, 최신순)에서 고르고, 주소에 값이 없으면 맨 위를 고른다.
    사건 큐에서 넘어온 trace_id가 목록(최근 50건)에 없어도 유지되도록 사용자 값을 허용한다."""
    q = inf("/incidents/recent?limit=50", [("option_text", "__text", "string"), ("trace_id", "__value", "string")])
    q.pop("refId"); q.pop("datasource")
    return {"type": "query", "name": "trace_id", "label": "사건", "hide": 0, "datasource": DS_B,
            "query": {"queryType": "infinity", "query": "", "refId": "var-trace_id", "infinityQuery": q},
            "refresh": 1, "sort": 0, "options": [], "current": {}, "includeAll": False, "multi": False,
            "allowCustomValue": True}


def inf_var(name, url, selector):
    q = inf(url, [(selector, selector, "string")])
    q.pop("refId"); q.pop("datasource")
    return {"type": "query", "name": name, "label": name, "hide": 2, "datasource": DS_B,
            "query": {"queryType": "infinity", "query": "", "refId": "var-" + name,
                      "infinityQuery": q},
            "refresh": 1, "options": [], "current": {}, "includeAll": False, "multi": False}


COMMON_VARS = [
    # 192.168.0.200 클러스터 NodePort (deploy/README.md). 인증 없는 Hubble UI는 내부망에서만 쓴다
    const("hubble_url", "http://192.168.0.200:31235", "Hubble UI URL"),
    const("headlamp_url", "http://192.168.0.200:31240", "Headlamp URL"),
]


def dashboard(key, title, b, variables, time_from="now-1h", refresh="", desc=""):
    return {
        "uid": UIDS[key], "title": title, "description": desc,
        "tags": ["tefal"], "editable": False, "graphTooltip": 1,
        "timezone": "browser", "schemaVersion": 39, "version": 1,
        "time": {"from": time_from, "to": "now"}, "refresh": refresh,
        "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
        "links": nav_links(),
        "templating": {"list": variables + COMMON_VARS},
        "annotations": {"list": []},
        "panels": b.panels,
    }


STATUS_MAP = {"type": "value", "options": {
    "blocked": {"text": "차단됨", "color": BLUE, "index": 0},
    "unblocked": {"text": "미차단", "color": RED, "index": 1},
    "pending": {"text": "판정 중", "color": GREY, "index": 2},
}}

# Sigma rule level (critical > high > medium > low > informational)
CRIT, YELLOW = "#C4162A", "#E0B400"
LEVELS = [("critical", "Critical", CRIT), ("high", "High", RED), ("medium", "Medium", ORANGE),
          ("low", "Low", YELLOW), ("informational", "Info", GREY)]
LEVEL_MAP = {"type": "value", "options": {
    k: {"text": t, "color": c, "index": i} for i, (k, t, c) in enumerate(LEVELS)}}


def label_map(text):
    return [{"type": "regex", "options": {"pattern": ".+", "result": {"text": text, "index": 0}}}]


def explore_tempo(trace_expr):
    u = DS_T["uid"]
    return ("/explore?left=%7B%22datasource%22:%22" + u + "%22,%22queries%22:%5B%7B%22refId%22:%22A%22,"
            "%22datasource%22:%7B%22type%22:%22tempo%22,%22uid%22:%22" + u + "%22%7D,"
            "%22queryType%22:%22traceql%22,%22query%22:%22" + trace_expr +
            "%22%7D%5D,%22range%22:%7B%22from%22:%22now-24h%22,%22to%22:%22now%22%7D%7D")


INCIDENT_LINK = ("/d/" + UIDS["incident"] + "?var-trace_id=${__data.fields.trace_id}"
                 "&from=${__data.fields.window_from_ms}&to=${__data.fields.window_to_ms}")



# ---------------------------------------------------------------------
# ① 계층별 방어 흐름 (Business Text). 화면 HTML은 백엔드 /flow/summary 의 html (app/flow_view.py),
# 모양은 목업 mockups/flow(2026-11-05 확정). 여기에는 스타일만 둔다.
# ---------------------------------------------------------------------
FLOW_CSS = ".tf{font-family:Inter,'Noto Sans KR',system-ui,sans-serif;color:#111827;display:flex;flex-direction:column;gap:12px;height:100%;padding:6px 10px;box-sizing:border-box}.tf a{text-decoration:none;color:inherit}.tf-head{display:flex;justify-content:space-between;align-items:center}.tf-title b{font-size:16px}.tf-title span{font-size:12px;color:#4B5563;margin-left:10px}.tf-meta{display:flex;gap:14px;align-items:center;font-size:12px}.tf-live{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;background:#FFF1E6;color:#B44A00;font-weight:600}.tf-live i{width:8px;height:8px;border-radius:50%;background:#F76808;animation:tfPulse 1.6s infinite}.tf-last{color:#1F4FB8;font-weight:600}.tf-body{display:flex;gap:20px;flex:1;min-height:0}.tf-left{flex:0 0 57%;display:flex;flex-direction:column;gap:10px;min-width:0}.tf-grid{display:grid;grid-template-columns:64px 58px 18px minmax(0,1fr) 18px minmax(0,1fr) 18px minmax(0,1fr) 18px 150px;column-gap:4px;align-items:center}.tf-colhead{padding:0 9px;font-size:11px;color:#4B5563;font-weight:600}.tf-colhead span{text-align:center}.tf-colhead span:first-child{text-align:left}.tf-box{position:relative;display:flex;flex-direction:column;gap:6px;padding:11px 8px 7px;border-radius:10px}.tf-box.tet{border:1px solid #DCE6F7;background:#F8FAFF}.tf-box.fal{border:1px solid #F7D4D5;background:#FFF8F8}.tf-tag{position:absolute;top:-8px;left:10px;padding:0 6px;background:#FFFFFF;font-size:10px;font-weight:700}.tet .tf-tag{color:#1E3A8A}.fal .tf-tag{color:#9B1C1F}.tf-name{font-size:14px;font-weight:700;white-space:nowrap}.fal .tf-name{font-size:13px}.tf-inc{text-align:center;font-size:18px;font-weight:700;border:1px solid #D1D5DB;border-radius:8px;padding:5px 0;background:#FFFFFF}.tf-cell{display:flex;align-items:baseline;justify-content:center;gap:6px;border-radius:8px;padding:6px 8px;min-width:0}.tf-cell b{font-size:18px}.tf-cell small{font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tf-cell.lv1{background:#DCE8FD;color:#1E3A8A}.tf-cell.lv2{background:#A9C7F9;color:#0F2A6B}.tf-cell.lv3{background:#2F64D6;color:#FFFFFF}.tf-cell.zero,.tf-cell.none{background:#F3F4F6;color:#4B5563}.tf-cell.recent{outline:2px solid #F76808;animation:tfPulse 1.6s infinite}.tf-arrow{width:18px;height:12px;justify-self:center;background-color:#D1D5DB;clip-path:polygon(0 5px,13.6px 5px,10.2px 1.6px,11.6px .2px,17.4px 6px,11.6px 11.8px,10.2px 10.4px,13.6px 7px,0 7px)}.tf-arrow.on{background-color:#9CA3AF;background-image:linear-gradient(90deg,transparent,#2F64D6,transparent);background-repeat:no-repeat;background-size:6px 12px;background-position:-6px 0;animation:tfGlow 2.6s ease-in-out infinite}.tf-wall{justify-self:center;width:11px;height:11px;margin-right:5px;border-top:3.5px solid #0E2C6E;border-right:3.5px solid #0E2C6E;transform:rotate(45deg)}.tf-result{display:flex;align-items:center;justify-content:space-between;background:#9EDB8F;color:#0E3B1A;border:1px solid #5DB55A;border-radius:8px;padding:6px 10px;font-size:12px}.tf-result b{font-size:15px}.tf-result small{color:#24562A;font-size:12px}.tf-falrow{display:grid;grid-template-columns:64px 58px minmax(0,1fr) 150px;column-gap:4px;align-items:center}.tf-dash{display:flex;align-items:center;gap:10px;color:#6B7280;font-size:12px;margin-left:22px}.tf-dash i{flex:1;height:2px;background:repeating-linear-gradient(90deg,#F3A5A8 0 6px,transparent 6px 12px);animation:tfDash 3s linear infinite}.tf-unblocked{display:flex;align-items:center;justify-content:center;background:#E5484D;color:#FFFFFF;border-radius:8px;padding:7px 10px;font-size:15px;font-weight:700}.tf-unblocked.zero{background:#F3F4F6;color:#4B5563}.tf-feed{flex:1;min-width:0;display:flex;flex-direction:column;gap:6px;border-left:1px solid #E5E7EB;padding-left:20px}.tf-feedhead{display:flex;justify-content:space-between;font-size:11px;color:#4B5563;font-weight:600}.tf-feedhead a{color:#1F60C4}.tf-item{display:grid;grid-template-columns:64px 54px minmax(0,1fr) auto;gap:8px;align-items:center;padding:6px 8px;border-radius:6px;border:1px solid #F3F4F6}.tf-item:hover{border-color:#D1D5DB}.tf-item.new{border-color:#FFD8B8;animation:tfIn .6s ease-out 1,tfNew 2.4s ease-out .6s 1 both}.tf-time{font-size:12px;color:#374151;font-variant-numeric:tabular-nums}.tf-svc{font-size:11px;font-weight:700;color:#1E3A8A;background:#DCE8FD;border-radius:4px;padding:2px 6px;text-align:center}.tf-svc.falco{color:#9B1C1F;background:#FDE2E3}.tf-path{font-size:12px;color:#374151;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tf-path b{color:#1F4FB8}.tf-badge{font-size:11px;font-weight:700;color:#0E3B1A;background:#9EDB8F;border:1px solid #5DB55A;border-radius:999px;padding:2px 8px}.tf-badge.bad{color:#FFFFFF;background:#E5484D;border-color:#E5484D}.tf-empty{font-size:12px;color:#6B7280;padding:8px}@keyframes tfPulse{0%{box-shadow:0 0 0 0 rgba(247,104,8,.55)}70%{box-shadow:0 0 0 8px rgba(247,104,8,0)}100%{box-shadow:0 0 0 0 rgba(247,104,8,0)}}@keyframes tfGlow{0%{background-position:-6px 0}100%{background-position:18px 0}}@keyframes tfDash{to{background-position:24px 0}}@keyframes tfIn{0%{transform:translateY(-8px);opacity:0}100%{transform:none;opacity:1}}@keyframes tfNew{0%{background:#FFF1E6}100%{background:#FFFFFF}}"


def flow_panel(b, y):
    target = inf("/flow/summary?" + TR + "&namespace=${namespace}", [("html", "html", "string")])
    p = b.add("marcusolsson-dynamictext-panel", "", 0, y, 24, 9, [target], DS_B,
              {"renderMode": "everyRow", "content": "{{{html}}}", "defaultContent": "계층별 방어 흐름을 불러오는 중…",
               "editors": ["styles"], "contentPartials": [], "helpers": "", "styles": FLOW_CSS,
               "wrap": False, "editor": {"language": "html", "format": "auto"}},
              desc="계층별 방어 흐름 · 사건 기준. 앱(uprobe) → 프로세스(kprobe) → 커널(LSM)에서 막혔는지, "
                   "Falco로만 탐지된 사건은 따로 보여 줍니다. 주황 테두리 = 최근 5분 활동. "
                   "줄을 누르면 운영 현황이 그 서비스로, 피드를 누르면 사건 상세로 갑니다.")
    return p


# =====================================================================
# ① 운영 현황
# =====================================================================
def overview():
    b = Builder()
    summary_url = "/incidents/summary?" + INC_Q

    p_unblocked = b.add("stat", "조치 필요 · 미차단", 0, 0, 6, 5,
          [inf(summary_url, [("unblocked_count", "미차단", "number"),
                             ("unblocked_last_time", "최근", "string")])],
          DS_B, stat_opts(size=(14, 48)),
          defaults={"unit": "none", "color": fixed(RED), "noValue": "0",
                    "mappings": [], "thresholds": thresholds((None, RED))},
          overrides=[ov("최근", color=fixed("text"))],
          desc="Falco만 탐지하고 Tetragon이 차단하지 못한 사건. 바로 조치가 필요합니다.")

    p_blocked = b.add("stat", "차단", 6, 0, 6, 5,
          [inf(summary_url, [("blocked_count", "차단 (건)", "number")])],
          DS_B, stat_opts(text="value", size=(14, 48)),
          defaults={"color": fixed(BLUE), "noValue": "0", "thresholds": thresholds((None, BLUE))},
          desc="Tetragon 인라인 차단(Sigkill·Override) 건수. 선택한 시간 범위 기준.")

    p_attacked = b.add("stat", "공격받은 워크로드", 12, 0, 6, 5,
          [inf(summary_url, [("attacked_workloads", "공격받음", "number"),
                             ("total_workloads", "전체 pod", "number")])],
          DS_B, stat_opts(size=(14, 48)),
          defaults={"color": fixed("text"), "noValue": "0", "thresholds": thresholds((None, "text"))},
          overrides=[ov("전체 pod", color=fixed(GREY))],
          desc="사건이 1건 이상 발생한 pod 수 / 필터에 걸리는 Running pod 수")

    health_map = [{"type": "range", "options": {"from": 1, "to": 1e9, "result": {"text": "정상", "color": GREEN, "index": 0}}},
                  {"type": "range", "options": {"from": -1e9, "to": 0.9999, "result": {"text": "이상", "color": RED, "index": 1}}}]
    b.add("stat", "수집 상태", 18, 0, 6, 5,
          [prom('sum(kube_daemonset_status_number_ready{daemonset=~".*tetragon.*"}) / sum(kube_daemonset_status_desired_number_scheduled{daemonset=~".*tetragon.*"})', "Tetragon", "A"),
           prom('sum(kube_daemonset_status_number_ready{daemonset=~".*falco.*"}) / sum(kube_daemonset_status_desired_number_scheduled{daemonset=~".*falco.*"})', "Falco", "B"),
           prom('min(up{job=~".*(alloy|loki|tempo).*"})', "Alloy → Loki / Tempo", "C")],
          DS_P, stat_opts(fields="", size=(14, 16), orient="horizontal", color="value"),
          defaults={"mappings": health_map, "noValue": "수신 없음",
                    "thresholds": thresholds((None, RED), (1, GREEN))},
          desc="DaemonSet Ready 비율과 Alloy/Loki/Tempo scrape 상태. 1이면 정상입니다.")

    b.add("stat", "경고 단계별 탐지 · 로그 기준 (Sigma level)", 0, 5, 24, 4,
          [inf("/policies/levels?" + TR + "&namespace=${namespace}",
               [("level_" + k + "_count", t, "number") for k, t, _ in LEVELS])],
          DS_B, stat_opts(size=(14, 32), orient="vertical", color="background"),
          defaults={"unit": "none", "noValue": "0", "color": fixed(GREY),
                    "thresholds": thresholds((None, GREY))},
          overrides=[ov(t, color=fixed(c)) for _, t, c in LEVELS],
          # Infinity가 열을 알파벳순으로 바꾸므로 높은 단계부터 순서를 고정한다
          transformations=[{"id": "organize", "options": {"indexByName": {t: i for i, (_, t, _) in enumerate(LEVELS)}}}],
          desc="Tetragon·Falco 탐지를 정책·룰의 Sigma level별로 더한 값입니다. "
               "같은 프로세스의 같은 행위가 1초 안에 반복되면 1건으로 셉니다. "
               "공격 1번에 탐지가 여러 건 나오므로 사건 수와 단위가 다릅니다(사건별 단계는 사건 큐의 '단계' 열). "
               "namespace·시간 범위만 적용되고 런타임·상태·단계 필터는 적용되지 않습니다. "
               "Tetragon은 지금 클러스터에 적용된 정책의 로그만 셉니다. "
               "매칭 표는 tefal-backend의 sigma_levels.yaml, 표에 없는 정책·룰은 Info.")

    queue_cols = [
        ("time", "시각", "string"), ("level", "단계", "string"), ("status", "상태", "string"),
        ("workload", "namespace / pod", "string"), ("runtime", "런타임", "string"),
        ("summary", "행위 요약", "string"), ("mitre_text", "MITRE", "string"),
        ("src_ip_text", "출발지 IP", "string"),
        ("trace_id", "트레이스", "string"),
        ("trace_id", "trace_id", "string"),
        ("window_from_ms", "window_from_ms", "number"), ("window_to_ms", "window_to_ms", "number"),
        ("src_ip", "src_ip", "string"),  # 링크용 원래 값 (표시 열에는 '· 시연용'이 붙을 수 있다)
    ]
    p_queue = b.add("table", "사건 큐 · trace 1개 = 사건 1건 (미차단 우선 정렬)", 0, 9, 24, 10,
          [inf("/incidents?" + INC_Q + "&limit=100", queue_cols)],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}, "inspect": False},
                    "noValue": "사건 없음"},
          overrides=[
              ov("시각", custom__width=100),
              ov("단계", custom__width=90, mappings=[LEVEL_MAP],
                 custom__cellOptions={"type": "color-background", "mode": "basic"}),
              ov("상태", custom__width=90, mappings=[STATUS_MAP],
                 custom__cellOptions={"type": "color-background", "mode": "basic"}),
              ov("런타임", custom__width=80),
              ov("MITRE", custom__width=110),
              ov("출발지 IP", custom__width=190, color=fixed(BLUE),
                 custom__cellOptions={"type": "color-text"},
                 # 출발지를 모르면 '확인 불가 (이유)'가 온다 → 회색
                 mappings=[{"type": "regex", "options": {"pattern": "^확인 불가.*",
                                                          "result": {"color": GREY, "index": 0}}}],
                 links=[{"title": "위협 인텔리전스에서 보기",
                         "url": "/d/" + UIDS["ti"] + "?var-ip=${__data.fields.src_ip}&from=now-24h&to=now"}]),
              # Trace View와 AI 해석이 함께 있는 사건 상세로 간다 (Tempo Explore는 Trace View 패널에서)
              ov("트레이스", custom__width=90, mappings=label_map("트레이스"),
                 links=[{"title": "사건 상세 · Trace View + AI 해석", "url": INCIDENT_LINK}]),
              hide("trace_id"), hide("window_from_ms"), hide("window_to_ms"), hide("src_ip"),
          ],
          desc="출처: tefal-backend /incidents. 미차단이 먼저, 그다음 최신순. 단계는 Sigma level, 판정 중 = Falco 경보 후 Tetragon 결과 대기.")

    p_workload = b.add("barchart", "워크로드별 사건 · 패치·격리 우선순위", 0, 19, 12, 8,
          [inf("/incidents/by-workload?" + INC_Q,
               [("pod", "pod", "string"), ("blocked", "차단", "number"), ("unblocked", "미차단", "number")])],
          DS_B,
          {"orientation": "horizontal", "xField": "pod", "stacking": "normal",
           "showValue": "auto", "barWidth": 0.5, "groupWidth": 0.7, "fullHighlight": False,
           "legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
           "tooltip": {"mode": "multi", "sort": "none"}, "xTickLabelRotation": 0},
          defaults={"custom": {"fillOpacity": 90, "lineWidth": 0, "axisPlacement": "auto"},
                    "unit": "none", "decimals": 0},
          overrides=[ov("차단", color=fixed(BLUE)), ov("미차단", color=fixed(RED))],
          desc="미차단이 많은 워크로드부터 패치·격리합니다.")

    p_timeline = b.add("timeseries", "시간대별 사건 (5분 단위)", 12, 19, 12, 8,
          [inf("/incidents/timeseries?" + INC_Q + "&interval=5m",
               [("time_ms", "time", "timestamp_epoch"), ("blocked", "차단", "number"),
                ("unblocked", "미차단", "number")])],
          DS_B,
          {"legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
           "tooltip": {"mode": "multi", "sort": "none"}},
          defaults={"custom": {"drawStyle": "bars", "fillOpacity": 90, "lineWidth": 0,
                               "barAlignment": 0, "stacking": {"mode": "normal", "group": "A"},
                               "showPoints": "never"},
                    "unit": "none", "decimals": 0, "min": 0},
          overrides=[ov("차단", color=fixed(BLUE)), ov("미차단", color=fixed(RED))])

    b.add("table", "정책 상태", 0, 27, 24, 9,
          [inf("/policies/stats?" + TR + "&namespace=${namespace}",
               [("policy", "정책", "string"), ("tag", "구분", "string"), ("layer", "계층", "string"),
                ("action", "액션", "string"), ("hits", "히트", "number")])],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}}},
          overrides=[
              ov("구분", custom__width=110), ov("계층", custom__width=170), ov("액션", custom__width=130),
              ov("히트", custom__width=70, custom__align="right"),
          ],
          desc="정책별 시간 범위 안 히트 수 (Tetragon·Falco 로그 기준, 같은 프로세스의 같은 행위가 1초 안에 반복되면 1건). 구분 = 경고 단계")

    # 상단 숫자를 누르면 관련 패널을 크게 연다 (Grafana 11+ viewPanel=panel-<id>).
    # 필터 변수와 시간 범위는 그대로 가져간다
    def view(panel, title, status="${status:queryparam}"):
        return [{"title": title, "url": "/d/" + UIDS["overview"] + "?${__url_time_range}"
                 "&${namespace:queryparam}&${runtime:queryparam}&${level:queryparam}&" + status
                 + f"&viewPanel=panel-{panel['id']}"}]
    p_unblocked["fieldConfig"]["defaults"]["links"] = view(p_queue, "처리할 사건 목록 (미차단)", "var-status=unblocked")
    p_blocked["fieldConfig"]["defaults"]["links"] = view(p_timeline, "시간대별 사건 그래프")
    p_attacked["fieldConfig"]["defaults"]["links"] = view(p_workload, "워크로드별 사건 막대그래프")
    # 사건 큐: 아무 칸이나 누르면 사건 상세. 출발지 IP·트레이스 칸은 열별 링크가 기본값을 덮으므로 사건 상세를 함께 둔다
    incident_link = {"title": "사건 상세 · Trace View + AI 해석", "url": INCIDENT_LINK}
    p_queue["fieldConfig"]["defaults"]["links"] = [incident_link]
    for o in p_queue["fieldConfig"]["overrides"]:
        for prop in o["properties"]:
            if prop["id"] == "links" and incident_link not in prop["value"]:
                prop["value"] = [incident_link, *prop["value"]]

    # 계층별 방어 흐름을 맨 위(필터 줄 바로 아래)에 둔다. 다른 패널은 9칸 내리고 경고 단계 칸은 4 → 3
    flow_h = 9
    for panel in b.panels:
        panel["gridPos"]["y"] += flow_h
        if panel["title"].startswith("경고 단계별 탐지"):
            panel["gridPos"]["h"] = 3
    flow_panel(b, 0)

    variables = [
        {"type": "query", "name": "namespace", "label": "namespace", "hide": 0, "datasource": DS_P,
         "query": {"query": "label_values(kube_pod_info, namespace)", "refId": "ns"},
         "definition": "label_values(kube_pod_info, namespace)", "refresh": 1, "sort": 1,
         "includeAll": True, "allValue": "All", "multi": False,
         "current": {"text": "All", "value": "$__all"}, "options": []},
        custom("runtime", "runtime", "Java,PHP,Node", multi=True),
        custom("status", "상태", "차단됨 : blocked,미차단 : unblocked,판정 중 : pending"),
        custom("level", "단계", ",".join(f"{t} : {k}" for k, t, _ in LEVELS), multi=True),
    ]
    return dashboard("overview", "운영 현황", b, variables, refresh="5s",
                     desc="TEFAL 메인 · 사건 큐, 차단 현황, 정책 상태")


# =====================================================================
# ② 사건 상세 + AI 해석
# =====================================================================
def incident():
    b = Builder()
    # 드롭다운으로 사건을 바꾸면 대시보드 시간 범위는 그대로라, 사건 시각 ±5분으로 다시 여는 링크를 둔다
    fit_time = {"title": "이 사건 시각으로 맞추기 (±5분)",
                "url": "/d/" + UIDS["incident"] + "?var-trace_id=${trace_id}"
                       "&from=${__data.fields.window_from_ms}&to=${__data.fields.window_to_ms}"}
    b.add("stat", "사건 요약", 0, 0, 24, 4,
          [inf("/incidents/${trace_id}",
               [("status_text", "상태", "string"), ("workload", "워크로드", "string"),
                ("runtime_detail", "런타임", "string"), ("time_text", "시작", "string"),
                ("mitre_text", "MITRE", "string"), ("src_ip_text", "출발지 IP", "string"),
                ("window_from_ms", "window_from_ms", "number"), ("window_to_ms", "window_to_ms", "number")])],
          DS_B, {**stat_opts(fields="/^(상태|워크로드|런타임|시작|MITRE|출발지 IP)$/", size=(12, 18), color="none"),
                 "colorMode": "none"},
          defaults={"noValue": "사건을 선택하세요", "links": [fit_time]},
          links=[fit_time, {"title": "← 사건 큐", "url": "/d/" + UIDS["overview"] + "?from=now-1h&to=now"}])

    tv = b.add("traces", "Trace View · 계층별 인과 흐름", 0, 4, 15, 15,
               # Grafana 화면의 Tempo 데이터소스는 queryType "traceId"를 실행하지 않는다(패널이 계속 로딩).
               # traceql 쿼리에 trace ID만 넣으면 화면이 trace 조회로 바꿔 보낸다.
               [{"refId": "A", "datasource": DS_T, "queryType": "traceql", "query": "${trace_id}"}],
               DS_T, {},
               # ① 큐의 '트레이스' 버튼이 이 화면으로 오므로, Tempo Explore는 패널 링크로 남긴다
               links=[{"title": "Tempo Explore에서 열기", "url": explore_tempo("${trace_id}"), "targetBlank": True}],
               desc="출처: Tempo. span을 누르면 binary/args, policy·action, exec_id/parent를 볼 수 있습니다. "
                    "계층: app·uprobe → proc → kernel·LSM → falco")
    # Grafana는 trace ID 조회에도 대시보드 시간 범위를 붙인다. 사건 시각 ±5분으로는 늦게 기록된
    # trace(백엔드 재시작·재생성으로 지난 사건을 다시 기록한 경우)를 못 찾으므로 이 패널만 최근 7일로 찾는다.
    tv["timeFrom"] = "7d"
    tv["hideTimeOverride"] = True

    # 사람이 요청할 때만 Gemini를 부른다. 버튼은 이 화면을 ai_req를 붙여 다시 여는 링크다(백엔드 routers/ai.py).
    btn = ("display:inline-block;margin-top:8px;padding:6px 14px;border-radius:4px;"
           "background:#3871DC;color:#fff;text-decoration:none;font-weight:500")
    # 텍스트 패널은 ${__from} 같은 내장 변수를 바꾸지 않아서 응답의 사건 구간으로 시간 범위를 붙인다
    here = "/d/" + UIDS["incident"] + "?var-trace_id={{trace_id}}&from={{window_from_ms}}&to={{window_to_ms}}"
    ai_content = "\n".join([
        '{{#if message}}<p style="color:#FF9830">{{message}}</p>{{/if}}',
        "{{#if markdown}}",
        "{{{markdown}}}",
        "",
        f'<a href="{here}&var-ai_req=refresh:{{{{trace_id}}}}:{{{{created_ms}}}}" style="{btn};background:#5A6171">↻ 다시 분석</a>',
        "{{else}}",
        "아직 AI 분석을 하지 않은 사건입니다.",
        "",
        "요청하면 Gemini가 이 사건의 근거 로그를 읽고 판정·MITRE·대응 가이드를 만듭니다 (몇 초 걸립니다).",
        "",
        f'<a href="{here}&var-ai_req=run:{{{{trace_id}}}}" style="{btn}">AI 분석 요청</a>',
        "{{/if}}",
    ])
    b.add("marcusolsson-dynamictext-panel", "AI 해석 · 대응 가이드", 15, 4, 9, 15,
          [inf("/ai/analysis/${trace_id}?req=${ai_req}",
               [("trace_id", "trace_id", "string"), ("markdown", "markdown", "string"),
                ("created_ms", "created_ms", "number"), ("message", "message", "string"),
                ("window_from_ms", "window_from_ms", "number"), ("window_to_ms", "window_to_ms", "number")])],
          DS_B,
          {"renderMode": "everyRow", "content": ai_content, "defaultContent": "AI 분석을 불러오는 중…",
           "editors": ["helpers"], "contentPartials": [], "helpers": "", "styles": "",
           "wrap": True, "editor": {"language": "markdown", "format": "auto"}},
          desc="Gemini가 근거 로그를 바탕으로 생성합니다. 화면을 열 때는 저장된 결과만 보여 주고, "
               "[AI 분석 요청]·[다시 분석]을 눌러야 Gemini를 부릅니다.")

    b.add("logs", "원본 로그 · 이 사건에 속한 이벤트", 0, 19, 16, 9,
          # `"exec_id":"<값>"`로 거른다: process·parent의 exec_id와 parent_exec_id에 모두 맞고,
          # 값이 비면(사건 미선택) `"exec_id":""`가 되어 아무 줄에도 맞지 않는다
          [{"refId": "A", "datasource": DS_L, "expr": '${loki_selector} |= `"exec_id":"${exec_id}"`', "queryType": "range"},
           {"refId": "B", "datasource": DS_L, "expr": '${loki_selector} |= `"exec_id":"${parent_exec_id}"`', "queryType": "range"}],
          DS_L,
          {"showTime": True, "showLabels": False, "showCommonLabels": False, "wrapLogMessage": True,
           "prettifyLogMessage": True, "enableLogDetails": True, "dedupStrategy": "numbers",
           "sortOrder": "Ascending"},
          desc="출처: Loki · exec_id 와 parent exec_id 로 필터. JSON을 줄바꿈해 보여 줍니다(Prettify JSON). "
               "숫자(시각 등)만 다른 연속 줄은 한 줄로 접어 반복 횟수를 표시합니다 (중복 제거: Numbers)")

    b.add("stat", "출발지 IP 요약", 16, 19, 8, 9,
          [inf("/ti/ip/${src_ip}",
               [("ip", "IP", "string"), ("country_asn", "국가 / ASN", "string"),
                ("abuse_score", "AbuseIPDB 점수", "number"), ("vt_text", "VirusTotal", "string"),
                ("notice", "안내", "string")])],
          DS_B, {**stat_opts(fields="/.*/", size=(12, 18)), "orientation": "horizontal"},
          defaults={"color": fixed("text"), "noValue": "출발지 IP 확인 불가 · 사설 IP는 평판 조회를 하지 않음",
                    "thresholds": thresholds((None, "text"))},
          overrides=[ov("AbuseIPDB 점수", unit="none", max=100, color={"mode": "thresholds"},
                        thresholds=thresholds((None, GREY), (25, ORANGE), (75, RED)))],
          links=[{"title": "TI 탭에서 보기 →",
                  "url": "/d/" + UIDS["ti"] + "?var-ip=${src_ip}&from=now-24h&to=now"}])

    variables = [
        incident_picker(),
        textbox("ai_req", "AI 요청") | {"hide": 2},  # 버튼이 주소에 붙이는 값. 평소엔 비어 있다
        inf_var("src_ip", "/incidents/${trace_id}", "src_ip"),
        inf_var("exec_id", "/incidents/${trace_id}", "exec_id"),
        inf_var("parent_exec_id", "/incidents/${trace_id}", "parent_exec_id"),
        const("loki_selector", '{namespace="kube-system", container="export-stdout"}', "Loki 셀렉터"),
    ]
    return dashboard("incident", "사건 상세", b, variables, time_from="now-1h",
                     desc="사건 1건의 Trace, 원본 로그, AI 해석. 사건 큐에서 들어오면 사건 시각 ±5분으로 열립니다.")


# =====================================================================
# ③ 위협 인텔리전스
# =====================================================================
def threat_intel():
    b = Builder()
    ti_cols = [("ip", "IP", "string"), ("role", "구분", "string"), ("country", "국가", "string"),
               ("asn_isp", "ASN / ISP", "string"),
               ("abuse_score", "Abuse 점수", "number"), ("abuse_reports", "신고 수", "number"),
               ("vt_text", "VT 악성", "string"), ("related_incidents", "관련 사건", "number"),
               ("last_checked", "최근 조회", "string"),
               ("lat", "lat", "number"), ("lon", "lon", "number")]
    ips_url = "/ti/ips?" + TR + "&min_abuse=${min_abuse}"
    abuse_thr = thresholds((None, GREY), (25, ORANGE), (75, RED))

    b.add("geomap", "TI 대상 IP 위치 · 색 = Abuse 점수", 0, 0, 16, 12,
          [inf(ips_url, ti_cols)], DS_B,
          {"view": {"id": "zero", "lat": 20, "lon": 10, "zoom": 1.6, "allLayers": True},
           "controls": {"showZoom": True, "mouseWheelZoom": True, "showAttribution": True},
           # CARTO(Grafana Default 포함)는 키 없는 요청에 'API KEY REQUIRED' 그림을 준다 → OpenStreetMap
           "basemap": {"type": "osm-standard", "name": "basemap", "config": {}},
           "layers": [{
               "type": "markers", "name": "TI 대상 IP", "tooltip": True,
               "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
               "config": {"showLegend": True, "style": {
                   "size": {"fixed": 9, "min": 4, "max": 15},
                   "color": {"field": "Abuse 점수", "fixed": GREY},
                   "opacity": 0.9, "symbol": {"mode": "fixed", "fixed": "img/icons/marker/circle.svg"},
                   "text": {"mode": "field", "field": "IP", "fixed": ""},
                   "textConfig": {"fontSize": 12, "offsetX": 14, "offsetY": 0,
                                  "textAlign": "left", "textBaseline": "middle"}}}}],
           "tooltip": {"mode": "details"}},
          defaults={"color": {"mode": "thresholds"}, "thresholds": abuse_thr, "min": 0, "max": 100},
          desc="Geomap 패널 · GeoIP (MaxMind). 대상 = 사건 출발지 + 감시 pod가 밖으로 연결한 공인 IP. "
               "75 이상 고위험(빨강), 25–74(주황), 25 미만/정보 없음(회색). "
               "사설 IP(10/8, 172.16/12, 192.168/16 등)는 외부로 보내지 않습니다. "
               "'출발지 (시연용)'은 시연 모드(DEMO_SRC_IP_POOL)로 바꾼 IP라 실제 공격 출발지가 아닙니다.")

    sum_url = "/ti/summary?" + TR
    b.add("stat", "조회된 공인 IP", 16, 0, 4, 4, [inf(sum_url, [("public_ip_count", "IP", "number")])],
          DS_B, stat_opts(text="value"), defaults={"color": fixed("text"), "thresholds": thresholds((None, "text"))})
    b.add("stat", "고위험 (≥75)", 20, 0, 4, 4, [inf(sum_url, [("high_risk_count", "IP", "number")])],
          DS_B, stat_opts(text="value"), defaults={"color": fixed(RED), "thresholds": thresholds((None, RED))})
    b.add("stat", "AbuseIPDB 사용량", 16, 4, 4, 4,
          [inf(sum_url, [("abuseipdb_used", "사용", "number"), ("abuseipdb_limit", "일일 한도", "number")])],
          DS_B, stat_opts(size=(11, 22)), defaults={"color": fixed("text"), "thresholds": thresholds((None, "text"))},
          overrides=[ov("일일 한도", color=fixed(GREY))])
    b.add("stat", "VirusTotal 사용량", 20, 4, 4, 4,
          [inf(sum_url, [("virustotal_used", "사용", "number"), ("virustotal_limit", "일일 한도", "number")])],
          DS_B, stat_opts(size=(11, 22)), defaults={"color": fixed("text"), "thresholds": thresholds((None, "text"))},
          overrides=[ov("일일 한도", color=fixed(GREY))])
    b.add("stat", "캐시", 16, 8, 8, 4,
          [inf(sum_url, [("cache_hit_rate", "적중률", "number"), ("cache_ttl_hours", "재조회 간격 (시간)", "number")])],
          DS_B, stat_opts(size=(11, 22)),
          defaults={"color": fixed("text"), "thresholds": thresholds((None, "text"))},
          overrides=[ov("적중률", unit="percentunit", decimals=0)],
          desc="같은 IP는 TTL 동안 재조회하지 않습니다.")

    b.add("table", "IP 평판 · AbuseIPDB + VirusTotal", 0, 12, 24, 8,
          [inf(ips_url, ti_cols)], DS_B, table_opts(sort=[{"displayName": "Abuse 점수", "desc": True}]),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}}},
          overrides=[
              ov("IP", custom__width=150, links=[{"title": "이 IP 상세 보기",
                                                 "url": "/d/" + UIDS["ti"] + "?var-ip=${__value.raw}&${__url_time_range}"}]),
              ov("구분", custom__width=130, mappings=[{"type": "regex", "options": {
                  "pattern": ".*시연용.*", "result": {"color": ORANGE, "index": 0}}}],
                 custom__cellOptions={"type": "color-text"}),
              ov("국가", custom__width=60),
              ov("Abuse 점수", custom__width=220, min=0, max=100, color={"mode": "thresholds"},
                 thresholds=abuse_thr,
                 custom__cellOptions={"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}),
              ov("신고 수", custom__width=80), ov("VT 악성", custom__width=90),
              ov("관련 사건", custom__width=90, color=fixed(BLUE), custom__cellOptions={"type": "color-text"},
                 links=[{"title": "운영 현황 사건 큐", "url": "/d/" + UIDS["overview"] + "?${__url_time_range}"}]),
              ov("최근 조회", custom__width=90),
              hide("lat"), hide("lon"),
          ],
          desc="출처: tefal-backend /ti (Infinity)")

    ip_url = "/ti/ip/${ip}"
    b.add("stat", "선택 IP 상세 · ${ip}", 0, 20, 12, 5,
          [inf(ip_url, [("abuse_score", "Abuse 신뢰 점수", "number"), ("last_reported", "최근 신고", "string"),
                        ("usage_type", "용도", "string"), ("is_tor", "Tor 노드", "string"),
                        ("notice", "안내", "string")])],
          DS_B, stat_opts(fields="/.*/", size=(12, 18)),
          defaults={"color": fixed("text"), "noValue": "IP 조회 변수에 공인 IP를 입력하세요",
                    "thresholds": thresholds((None, "text"))},
          overrides=[ov("Abuse 신뢰 점수", color={"mode": "thresholds"}, thresholds=abuse_thr),
                     ov("Tor 노드", mappings=[{"type": "value", "options": {
                         "true": {"text": "예", "color": RED, "index": 0},
                         "false": {"text": "아니오", "index": 1}}}])])
    b.add("stat", "AbuseIPDB 신고 분류 · VirusTotal 판정", 0, 25, 12, 4,
          [inf(ip_url, [("abuse_categories_text", "신고 분류", "string"),
                        ("vt_malicious", "악성", "number"), ("vt_suspicious", "의심", "number"),
                        ("vt_harmless", "무해", "number"), ("vt_undetected", "미분류", "number")])],
          DS_B, stat_opts(fields="/.*/", size=(11, 16)),
          defaults={"color": fixed("text"), "noValue": "—", "thresholds": thresholds((None, "text"))},
          overrides=[ov("악성", color=fixed(RED)), ov("의심", color=fixed(ORANGE))])

    b.add("table", "파일 해시 조회 · 업로드된 웹셸", 12, 20, 12, 9,
          [inf("/ti/files?" + TR + "&ip=${ip}",
               [("path", "파일", "string"), ("sha256", "SHA-256", "string"),
                ("vt_malicious", "VT 악성", "number"), ("message", "판정", "string")])],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}, "inspect": True},
                    "noValue": "파일 해시 수집 전 (Tetragon IMA 해시 정책 필요)"},
          overrides=[ov("VT 악성", custom__width=80, color={"mode": "thresholds"},
                        thresholds=thresholds((None, BLUE), (1, RED)),
                        custom__cellOptions={"type": "color-text"}),
                     ov("SHA-256", custom__width=200)],
          links=[{"title": "관련 사건 보기 →", "url": "/d/" + UIDS["overview"] + "?${__url_time_range}"}],
          desc="VirusTotal 파일 해시 조회. Tetragon 로그에 파일 해시가 없어 아직 비어 있습니다 "
               "(IMA 해시 수집 정책을 켜면 연결). 기록이 없어도 Tetragon이 행위 기준으로 차단했을 수 있습니다.")

    variables = [textbox("ip", "IP 조회"), textbox("min_abuse", "최소 Abuse 점수", "0")]
    return dashboard("ti", "위협 인텔리전스", b, variables, time_from="now-24h",
                     desc="출발지 IP 평판(AbuseIPDB·VirusTotal), GeoIP, 파일 해시")


# =====================================================================
# ④ 인프라
# =====================================================================
def infra():
    b = Builder()
    big = stat_opts(size=(12, 40))
    b.add("stat", "노드", 0, 0, 6, 4,
          [prom('sum(kube_node_status_condition{condition="Ready",status="true"})', "Ready", "A"),
           prom('count(kube_node_info)', "전체", "B")],
          DS_P, big, defaults={"color": fixed(GREEN), "thresholds": thresholds((None, GREEN))},
          overrides=[ov("전체", color=fixed(GREY))])
    b.add("stat", "보호 대상 워크로드", 6, 0, 6, 4,
          [prom('count(kube_pod_status_phase{namespace=~"${watch_ns}",phase="Running"} == 1)', "Running pod", "A")],
          DS_P, big, defaults={"color": fixed("text"), "thresholds": thresholds((None, "text"))},
          desc="namespace ${watch_ns} 의 Running pod 수")
    b.add("stat", "적용된 정책", 12, 0, 6, 4,
          [inf("/infra/policies", [("total", "전체", "number"), ("tracing_policies", "TracingPolicy", "number"),
                                   ("falco_custom_rules", "Falco 커스텀", "number")])],
          DS_B, big, defaults={"color": fixed("text"), "thresholds": thresholds((None, "text"))},
          overrides=[ov("TracingPolicy", color=fixed(GREY)), ov("Falco 커스텀", color=fixed(GREY))])
    b.add("stat", "격리된 워크로드", 18, 0, 6, 4,
          [inf("/infra/policies", [("isolated_workloads", "CiliumNetworkPolicy", "number")])],
          DS_B, big, defaults={"color": {"mode": "thresholds"},
                               "thresholds": thresholds((None, "text"), (1, ORANGE))},
          desc="격리용 CiliumNetworkPolicy(tefal.io/isolate=true)가 걸린 pod 수")

    b.add("table", "노드", 0, 4, 12, 6,
          [inf("/infra/nodes", [("node", "노드", "string"), ("ready", "상태", "string"),
                                ("role", "역할", "string"), ("kernel", "커널", "string"),
                                ("bpf_lsm", "BPF LSM", "string"), ("pods", "Pod", "number")])],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}}},
          overrides=[
              ov("상태", custom__cellOptions={"type": "color-text"}, mappings=[{"type": "value", "options": {
                  "true": {"text": "● Ready", "color": GREEN, "index": 0},
                  "false": {"text": "● NotReady", "color": RED, "index": 1}}}]),
              ov("BPF LSM", custom__cellOptions={"type": "color-text"}, mappings=[{"type": "value", "options": {
                  "true": {"text": "활성", "color": GREEN, "index": 0},
                  "false": {"text": "비활성", "color": RED, "index": 1},
                  # 노드 라벨이 없고 LSM 이벤트도 관측되지 않은 노드 (예: 취약 앱이 없는 master)
                  "unknown": {"text": "확인 안 됨", "color": GREY, "index": 2}}}]),
          ],
          desc="K8s API. BPF LSM: 노드 라벨 tefal.io/bpf-lsm, 없으면 최근 7일 Tetragon process_lsm 이벤트 관측 여부")

    b.add("bargauge", "노드 리소스", 12, 4, 12, 6,
          [prom('100 * (1 - avg by (nodename) (rate(node_cpu_seconds_total{mode="idle"}[5m]) '
                '* on(instance) group_left(nodename) node_uname_info))', "{{nodename}} · CPU", "A"),
           prom('100 * (1 - avg by (nodename) ((node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) '
                '* on(instance) group_left(nodename) node_uname_info))', "{{nodename}} · 메모리", "B")],
          DS_P,
          {"orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
           "valueMode": "color", "namePlacement": "left", "sizing": "auto", "minVizHeight": 10,
           "reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""}},
          defaults={"unit": "percent", "min": 0, "max": 100, "decimals": 0,
                    "color": {"mode": "thresholds"},
                    "thresholds": thresholds((None, BLUE), (80, ORANGE), (90, RED))},
          # 메모리 막대는 보라색 (CPU는 기본 파란색). 행 단위 색을 쓰려면 seriesToRows가 아닌 join이어야 한다
          overrides=[{"matcher": {"id": "byRegexp", "options": ".*메모리$"},
                      "properties": [{"id": "thresholds",
                                      "value": thresholds((None, "#B877D9"), (80, ORANGE), (90, RED))}]}],
          # 노드별로 CPU → 메모리 순: 시계열을 Time으로 합친 뒤 순서를 지정한다.
          # organize의 이름 자동 정렬은 로케일 비교라 한글 "메모리"가 "CPU"보다 앞에 온다 → 노드 목록으로 직접 지정.
          # 목록에 없는 노드는 뒤에 붙는다
          transformations=[
              {"id": "joinByField", "options": {"byField": "Time", "mode": "outer"}},
              {"id": "organize", "options": {"indexByName": {"Time": 0, **{
                  f"{n} · {m}": 1 + i * 2 + j for i, n in enumerate(NODES) for j, m in enumerate(("CPU", "메모리"))}}}},
          ],
          desc="node-exporter 기준 CPU / 메모리 사용률")

    b.add("table", "워크로드 보호 현황", 0, 10, 16, 11,
          [inf("/infra/workloads?namespace=${watch_ns}",
               [("pod_label", "pod", "string"), ("status", "상태", "string"), ("restarts", "재시작", "number"),
                ("node", "노드", "string"), ("tetragon_policy", "Tetragon 정책", "string"),
                ("falco", "Falco", "string"), ("network", "네트워크", "string")])],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}}, "noValue": "—"},
          overrides=[
              ov("상태", custom__width=110, custom__cellOptions={"type": "color-text"},
                 mappings=[{"type": "value", "options": {"Running": {"text": "● Running", "color": GREEN, "index": 0}}},
                           {"type": "regex", "options": {"pattern": "(.+)", "result": {"text": "● $1", "color": RED, "index": 1}}}]),
              ov("재시작", custom__width=70, color={"mode": "thresholds"},
                 thresholds=thresholds((None, "text"), (1, ORANGE)), custom__cellOptions={"type": "color-text"}),
              ov("네트워크", mappings=[{"type": "special", "options": {"match": "empty", "result": {"text": "—", "index": 0}}}]),
              ov("Tetragon 정책", mappings=[{"type": "special", "options": {"match": "empty", "result": {"text": "—", "index": 0}}}]),
          ],
          desc="K8s API(pod 상태·재시작·노드) + 정책 매핑(TracingPolicy, Falco, CiliumNetworkPolicy)")

    b.add("table", "보안·관측 컴포넌트", 16, 10, 8, 11,
          [inf("/infra/components", [("name", "컴포넌트", "string"), ("kind", "종류", "string"),
                                     ("ready_text", "Ready", "string")])],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}}},
          overrides=[ov("종류", custom__width=80, color=fixed(GREY), custom__cellOptions={"type": "color-text"}),
                     ov("Ready", custom__width=70, custom__align="right",
                        custom__cellOptions={"type": "color-text"},
                        mappings=[{"type": "regex", "options": {"pattern": "^(\\d+)/\\1$", "result": {"color": GREEN, "index": 0}}},
                                  {"type": "regex", "options": {"pattern": ".*", "result": {"color": RED, "index": 1}}}])])

    b.add("table", "네트워크 · 정책에 막힌 흐름 (Hubble)", 0, 21, 12, 7,
          [inf("/network/drops?" + TR + "&namespace=${watch_ns}&limit=20",
               [("time_ms", "마지막", "timestamp_epoch"), ("src_pod", "출발", "string"), ("dst", "목적지", "string"),
                ("reason", "사유", "string"), ("policy", "정책", "string"), ("count", "횟수", "number")])],
          DS_B, table_opts(),
          defaults={"custom": {"align": "left", "cellOptions": {"type": "auto"}},
                    "noValue": "막힌 흐름 없음 (Hubble 버퍼 기준)"},
          overrides=[ov("마지막", custom__width=150, unit="dateTimeAsLocal"),
                     ov("사유", custom__width=130, color=fixed(ORANGE), custom__cellOptions={"type": "color-text"}),
                     ov("횟수", custom__width=60, custom__align="right")],
          desc="Hubble Relay GetFlows 에서 verdict=DROPPED 이고 감시 namespace pod 가 출발지나 목적지인 흐름. "
               "같은 출발→목적지·사유는 합쳐서 셉니다. 각 노드 Hubble 링 버퍼에 남은 흐름만 보이므로 오래된 구간은 비어 있을 수 있습니다")

    b.add("text", "관리 도구", 12, 21, 12, 7, [], None,
          {"mode": "html", "content":
           '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px">'
           '<a href="${hubble_url}" target="_blank" style="border:1px solid #5794F2;border-radius:4px;padding:6px 12px;color:#5794F2">Hubble UI · 서비스 맵 ↗</a>'
           '<a href="${headlamp_url}" target="_blank" style="border:1px solid #5794F2;border-radius:4px;padding:6px 12px;color:#5794F2">Headlamp · 격리·재시작 ↗</a>'
           '</div>'
           '<p style="opacity:0.75">Grafana는 조회 전용입니다. 조작은 별도 로그인과 최소 권한이 걸린 Headlamp에서만 합니다.</p>'})
    b.panels[-1].pop("datasource"); b.panels[-1].pop("targets")

    variables = [const("watch_ns", "vuln-lab", "감시 namespace")]
    return dashboard("infra", "인프라", b, variables, refresh="30s",
                     desc="노드, 워크로드 보호 현황, 보안·관측 컴포넌트, Hubble 차단 흐름")


os.makedirs(OUT, exist_ok=True)
for name, fn in [("01-overview", overview), ("02-incident", incident),
                 ("03-threat-intel", threat_intel), ("04-infra", infra)]:
    d = fn()
    with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(name, "panels:", len(d["panels"]))
