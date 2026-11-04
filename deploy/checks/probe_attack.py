"""최근 공격 확인 (읽기 전용, 마스터에서 실행). 인자: 몇 시간 전부터 볼지
1) Loki: 기준점(SIGKILL/OVERRIDE)과 정책 이름 집계
2) 백엔드: 같은 구간의 사건 목록 (Grafana pod 경유, 토큰은 pod 환경 변수)
3) 기준점마다 어느 사건(trace_id)에 들어갔는지, 빠진 기준점이 있는지
4) 새 사건의 Trace View 쿼리(Grafana → Tempo, 사건 시각 ±5분) 결과
"""
import collections, json, subprocess, sys, time, urllib.parse

HOURS = float(sys.argv[1]) if len(sys.argv) > 1 else 3
LOKI = "/api/v1/namespaces/monitoring/services/loki:3100/proxy/loki/api/v1/query_range"
SEL = '{namespace="kube-system", container="export-stdout"}'
now = time.time_ns()
start = now - int(HOURS * 3600 * 10**9)


def sh(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True).stdout


def loki(expr, s, e, limit=5000):
    p = urllib.parse.urlencode({"query": expr, "start": s, "end": e, "limit": limit, "direction": "forward"})
    d = json.loads(sh(["kubectl", "get", "--raw", f"{LOKI}?{p}"]))
    return sorted((int(t), l) for r in d["data"]["result"] for t, l in r["values"])


def iso_ns(v):
    from datetime import datetime, timezone
    base, _, frac = v.rstrip("Z").partition(".")
    sec = int(datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return sec * 10**9 + int(frac.ljust(9, "0")[:9])


def kst(ns):
    return time.strftime("%H:%M:%S", time.gmtime(ns / 1e9 + 9 * 3600)) + f".{(ns // 10**6) % 1000:03d}"


# 1) Loki 기준점
anchors = []
for _, l in loki(SEL + ' |~ "KPROBE_ACTION_(SIGKILL|OVERRIDE)"', start, now):
    e = json.loads(l)
    k = next(k for k in e if k.startswith("process_"))
    b = e[k]
    pod = b["process"].get("pod") or {}
    anchors.append({"t": iso_ns(e["time"]), "type": k, "policy": b.get("policy_name"), "action": b.get("action"),
                    "ns": pod.get("namespace"), "pod": pod.get("name"), "exec_id": b["process"]["exec_id"],
                    "parent": b["process"].get("parent_exec_id")})
print(f"== Loki 기준점 (최근 {HOURS}시간): {len(anchors)}건")
for k, v in collections.Counter((a["ns"], (a["pod"] or "")[:30], a["policy"], a["action"].removeprefix("KPROBE_ACTION_")) for a in anchors).most_common():
    print(f"  {v:4}  {k}")

# 모든 정책 이름 (관찰 정책 포함) — 최종 정책 적용 확인
pols = collections.Counter()
for _, l in loki(SEL + ' |= "policy_name"', start, now):
    e = json.loads(l)
    k = next(k for k in e if k.startswith("process_"))
    pols[(e[k].get("policy_name"), e[k].get("action", "").removeprefix("KPROBE_ACTION_"))] += 1
print("== 정책 이벤트 전체 (policy, action): 건수")
for k, v in sorted(pols.items()):
    print(f"  {v:5}  {k}")

# 2) 백엔드 사건
F, T = start // 10**6, now // 10**6
script = f"""B=http://tefal-backend.monitoring.svc:8000
wget -qO- --header "Authorization: Bearer $TEFAL_API_TOKEN" "$B/incidents?from={F}&to={T}&limit=1000"
"""
rows = json.loads(sh(["kubectl", "exec", "-i", "-n", "monitoring", "deploy/grafana", "-c", "grafana", "--", "sh", "-s"], script) or "[]")
print(f"== 백엔드 사건 (같은 구간): {len(rows)}건")
for r in sorted(rows, key=lambda r: r["start_ms"]):
    print(f"  {r['time_text']} {r['trace_id']} {r['pod'][:26]:26} {r['status']:9} {r['level']:13} m={r['member_count']:<4} "
          f"policy={r['policy']} beyla={r['beyla_link_confidence']} src={r['src_ip']} | {r['summary'][:50]}")

# 3) 기준점 → 사건 매칭 (사건 시간 범위 + pod 기준)
watched = {"vuln-lab"}
unmatched = collections.Counter()
per_inc = collections.Counter()
for a in anchors:
    if a["ns"] not in watched:
        unmatched[("감시 대상 밖", a["ns"])] += 1
        continue
    hit = [r for r in rows if r["pod"] == a["pod"] and r["start_ms"] - 1 <= a["t"] // 10**6 <= r["window_to_ms"] - 5 * 60 * 1000 + 1]
    if hit:
        per_inc[hit[0]["trace_id"]] += 1
    else:
        unmatched[("사건 없음", a["pod"], kst(a["t"]))] += 1
print("== 기준점 → 사건: 사건별 기준점 수")
for tid, n in per_inc.most_common():
    print(f"  {tid}: {n}")
print("== 사건에 안 들어간 기준점:", dict(unmatched) or "없음")

# 4) Trace View (Grafana → Tempo, 사건 시각 ±5분)
if rows:
    checks = "\n".join(
        f'''printf "%s " {r["trace_id"]}; curl -s -H "Content-Type: application/json" -H "$AUTH" -d '{{"from":"{r["window_from_ms"]}","to":"{r["window_to_ms"]}","queries":[{{"refId":"A","datasource":{{"type":"tempo","uid":"tempo-ds"}},"queryType":"traceId","query":"{r["trace_id"]}"}}]}}' http://localhost:3000/api/ds/query | head -c 160; echo'''
        for r in rows)
    script = 'U="${GF_SECURITY_ADMIN_USER:-admin}:${GF_SECURITY_ADMIN_PASSWORD}"\nAUTH="Authorization: Basic $(printf %s "$U" | base64 | tr -d \'\\n\')"\n' + checks
    out = sh(["kubectl", "exec", "-i", "-n", "monitoring", "deploy/grafana", "-c", "grafana", "--", "sh", "-s"], script)
    print("== Trace View (Grafana 쿼리, 사건 시각 ±5분)")
    for line in out.splitlines():
        tid, _, body = line.partition(" ")
        ok = '"frames"' in body and "error" not in body
        print(f"  {tid}: {'OK' if ok else 'FAIL'} {'' if ok else body[:120]}")
