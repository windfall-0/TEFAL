"""Loki의 Tetragon 로그 구조 파악용 (읽기 전용). 마스터에서 kubectl get --raw로 조회."""
import collections, json, subprocess, sys, time, urllib.parse

BASE = "/api/v1/namespaces/monitoring/services/loki:3100/proxy/loki/api/v1/query_range"
SEL = '{namespace="kube-system", container="export-stdout"}'


def q(expr, start_ns, end_ns, limit=5000, direction="backward"):
    p = urllib.parse.urlencode({"query": expr, "start": start_ns, "end": end_ns, "limit": limit, "direction": direction})
    out = subprocess.run(["kubectl", "get", "--raw", f"{BASE}?{p}"], capture_output=True, text=True, check=True).stdout
    vals = []
    for s in json.loads(out)["data"]["result"]:
        vals += [(int(t), l) for t, l in s["values"]]
    return sorted(vals)


now = time.time_ns()
mode = sys.argv[1]
if mode == "stats":
    vals = q(SEL + ' |~ "KPROBE_ACTION_(SIGKILL|OVERRIDE)"', now - 7 * 86400 * 10**9, now)
    c = collections.Counter()
    for t, l in vals:
        e = json.loads(l)
        k = next(iter(k for k in e if k.startswith("process_")))
        b = e[k]
        c[(k, b.get("policy_name"), b.get("function_name"), b.get("action"), b["process"]["pod"]["namespace"], b["process"]["pod"].get("workload"))] += 1
    print("total", len(vals), "first", vals[0][0] if vals else None, "last", vals[-1][0] if vals else None)
    for k, v in c.most_common(): print(v, k)
    # 기준점 시각 군집 (10초 간격)
    ts = [t for t, _ in vals]; groups = 0; prev = None
    for t in ts:
        if prev is None or t - prev > 10 * 10**9: groups += 1
        prev = t
    print("clusters(10s)", groups)
elif mode == "around":
    # 가장 최근 기준점 주변 이벤트
    vals = q(SEL + ' |~ "KPROBE_ACTION_(SIGKILL|OVERRIDE)"', now - 7 * 86400 * 10**9, now, limit=1)
    t0 = vals[-1][0]; e = json.loads(vals[-1][1])
    b = next(v for k, v in e.items() if k.startswith("process_"))
    pod = b["process"]["pod"]["name"]
    ev = q(SEL + f' |= "{pod}"', t0 - 60 * 10**9, t0 + 3 * 10**9)
    c = collections.Counter()
    for t, l in ev:
        x = json.loads(l); k = next(k for k in x if k.startswith("process_")); p = x[k]["process"]
        c[k] += 1
        print((t - t0) / 1e9, k, p["pid"], p["binary"], p.get("arguments", "")[:80], "| parent", x[k].get("parent", {}).get("pid"), x[k].get("parent", {}).get("binary"), x[k].get("policy_name"), x[k].get("action"))
    print(c)
elif mode == "types":
    vals = q(SEL, now - 3600 * 10**9, now, limit=5000)
    c = collections.Counter()
    for t, l in vals:
        x = json.loads(l); k = next((k for k in x if k.startswith("process_")), list(x)[0])
        ns = (x.get(k, {}).get("process", {}).get("pod") or {}).get("namespace")
        c[(k, ns)] += 1
    print(len(vals)); [print(v, k) for k, v in c.most_common()]
