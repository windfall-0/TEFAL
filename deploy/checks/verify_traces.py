"""모든 사건의 Trace View 쿼리를 Grafana로 확인 (읽기 전용). 패널과 같은 범위(최근 7일)."""
import collections, json, subprocess, time


def sh(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True).stdout


EXEC = ["kubectl", "exec", "-i", "-n", "monitoring", "deploy/grafana", "-c", "grafana", "--", "sh", "-s"]
now = int(time.time() * 1000)
rows = json.loads(sh(EXEC, f'wget -qO- --header "Authorization: Bearer $TEFAL_API_TOKEN" '
                           f'"http://tefal-backend.monitoring.svc:8000/incidents?from={now - 7 * 86400000}&to={now}&limit=1000"'))
print("사건", len(rows))
bad = 0
for r in sorted(rows, key=lambda r: r["start_ms"]):
    body = json.dumps({"from": "now-7d", "to": "now", "queries": [{"refId": "A", "datasource": {"type": "tempo", "uid": "tempo-ds"},
                                                                   "queryType": "traceId", "query": r["trace_id"]}]})
    script = ('U="${GF_SECURITY_ADMIN_USER:-admin}:${GF_SECURITY_ADMIN_PASSWORD}"\n'
              f"curl -s -u \"$U\" -H Content-Type:application/json -d '{body}' http://localhost:3000/api/ds/query")
    res = json.loads(sh(EXEC, script) or "{}").get("results", {}).get("A", {})
    if res.get("error") or not res.get("frames"):
        bad += 1
        print(f"  FAIL {r['time_text']} {r['trace_id']} {res.get('error', '')[:80]}")
        continue
    f = res["frames"][0]
    names = [x["name"] for x in f["schema"]["fields"]]
    spans = [dict(zip(names, v)) for v in zip(*f["data"]["values"])]
    dup = sum(1 for c in collections.Counter(s["spanID"] for s in spans).values() if c > 1)
    roots = sum(1 for s in spans if not s.get("parentSpanID"))
    ok = dup == 0 and roots == 1
    bad += not ok
    print(f"  {'OK  ' if ok else 'BAD '} {r['time_text']} {r['pod'][:22]:22} spans={len(spans):<4} dup={dup} roots={roots} "
          f"m={r['member_count']:<4} beyla={r['beyla_link_confidence']}")
print("문제 있는 사건:", bad)
