# Grafana pod 안에서 실행: 최신 사건 1건의 trace_id로 상세 API 호출. 인자: from_ms to_ms
B=http://tefal-backend.monitoring.svc:8000
H="Authorization: Bearer $TEFAL_API_TOKEN"
L=$(wget -qO- --header "$H" "$B/incidents?from=$1&to=$2&limit=1000")
echo "count $(echo "$L" | grep -o '"trace_id"' | wc -l)"
TID=$(echo "$L" | grep -o '"trace_id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
echo "== /incidents/$TID"
wget -qO- --header "$H" "$B/incidents/$TID"; echo
echo "== metrics"
wget -qO- "$B/metrics" | grep -E "^tefal_(collector_lag_seconds|incidents_total|collector_errors_total)"
