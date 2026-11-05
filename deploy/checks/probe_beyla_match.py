"""사건(기준점 시각)마다 같은 pod의 Beyla server span이 시각을 감싸는지 확인 (읽기 전용).
입력: /tmp/inc.txt (check_incidents.sh 결과)"""
import json, subprocess, urllib.parse

BASE = "/api/v1/namespaces/monitoring/services/tempo:3200/proxy"


def get(path, **params):
    out = subprocess.run(["kubectl", "get", "--raw", f"{BASE}{path}?{urllib.parse.urlencode(params)}"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def attr(lst, key):
    for a in lst:
        if a["key"] == key:
            v = a["value"]
            return next(iter(v.values()))
    return None


parts = open("/tmp/inc.txt").read().split("== ")[1:]
rows = json.loads({p.split("\n", 1)[0]: p.split("\n", 1)[1].strip() for p in parts}["incidents"])
for r in rows:
    a_ns = r["anchor_ms"] * 10**6
    start, end = r["anchor_ms"] // 1000 - 120, r["anchor_ms"] // 1000 + 30
    q = '{ resource.k8s.pod.name = "%s" && kind = server }' % r["pod"]
    res = get("/api/search", q=q, start=start, end=end, limit=50, spss=10)
    cover, near = [], []
    for t in res.get("traces", []):
        for ss in t.get("spanSets", []):
            for sp in ss.get("spans", []):
                s0 = int(sp["startTimeUnixNano"]); s1 = s0 + int(sp.get("durationNanos", 0))
                (cover if s0 <= a_ns <= s1 else near).append((t["traceID"], t.get("rootTraceName"), (a_ns - s0) / 1e9, int(sp.get("durationNanos", 0)) / 1e9))
    detail = ""
    if cover:
        tid = cover[0][0]
        tr = get(f"/api/v2/traces/{tid}")
        for b in tr["trace"]["resourceSpans"]:
            inst = attr(b["resource"]["attributes"], "service.instance.id")
            for ss in b["scopeSpans"]:
                for sp in ss["spans"]:
                    if sp.get("kind") == "SPAN_KIND_SERVER":
                        detail = f"client={attr(sp['attributes'], 'client.address')} path={attr(sp['attributes'], 'url.path')} inst={inst}"
    print(f"{r['time_text']} {r['pod'][:28]:28} 감싸는 span {len(cover)}개, 앞뒤 2분 span {len(near)}개 "
          f"{('| ' + str(cover[0][1]) + ' ' + detail) if cover else ''}")
