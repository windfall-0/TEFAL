"""Tempo에 들어온 Beyla trace 확인 (읽기 전용, kubectl get --raw로 API server 프록시 경유)."""
import collections, json, subprocess, time, urllib.parse

BASE = "/api/v1/namespaces/monitoring/services/tempo:3200/proxy"


def get(path, **params):
    q = urllib.parse.urlencode(params)
    out = subprocess.run(["kubectl", "get", "--raw", f"{BASE}{path}?{q}"], capture_output=True, text=True)
    if out.returncode:
        return {"_error": out.stderr.strip()[:200]}
    return json.loads(out.stdout)


now = int(time.time())
for days in (1, 7):
    start = now - days * 86400
    print(f"== 최근 {days}일 service.name 값")
    print(get("/api/v2/search/tag/resource.service.name/values", start=start, end=now))
    print(f"== 최근 {days}일 k8s.pod.name 값")
    print(get("/api/v2/search/tag/resource.k8s.pod.name/values", start=start, end=now))

start = now - 7 * 86400
res = get("/api/search", q='{ resource.k8s.namespace.name = "vuln-lab" && kind = server }', start=start, end=now, limit=500, spss=3)
traces = res.get("traces", [])
print("== vuln-lab server span trace 수(최대 500):", len(traces), res.get("_error", ""))
by = collections.defaultdict(list)
for t in traces:
    by[t.get("rootServiceName")].append(t)
for svc, ts in by.items():
    ts.sort(key=lambda t: int(t["startTimeUnixNano"]))
    first = time.strftime("%m-%d %H:%M", time.localtime(int(ts[0]["startTimeUnixNano"]) // 10**9))
    last = time.strftime("%m-%d %H:%M", time.localtime(int(ts[-1]["startTimeUnixNano"]) // 10**9))
    print(f"  {svc}: {len(ts)}건  {first} ~ {last}  예: {ts[-1].get('rootTraceName')}")

# 가장 최근 trace 하나의 span 속성 (client.address, pid 등 연결에 쓸 값이 있는지)
if traces:
    for svc, ts in by.items():
        tid = ts[-1]["traceID"]
        tr = get(f"/api/v2/traces/{tid}")
        attrs = set()
        res_attrs = set()
        for b in tr.get("trace", {}).get("resourceSpans", []):
            res_attrs |= {a["key"] for a in b.get("resource", {}).get("attributes", [])}
            for ss in b.get("scopeSpans", []):
                for sp in ss.get("spans", []):
                    attrs |= {a["key"] for a in sp.get("attributes", [])}
        print(f"== {svc} trace {tid}\n  resource: {sorted(res_attrs)}\n  span: {sorted(attrs)}")
