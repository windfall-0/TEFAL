# Grafana pod 안에서 실행 (토큰은 pod 환경 변수, 출력하지 않음). 인자: from_ms to_ms
B=http://tefal-backend.monitoring.svc:8000
Q='namespace=$__all&runtime=Java,PHP,Node&status=$__all&level=critical,high,medium,low,informational'
Q="from=$1&to=$2&$Q"
for p in "incidents/summary" "incidents/by-workload" "incidents/timeseries" "incidents"; do
  echo "== $p"
  wget -qO- --header "Authorization: Bearer $TEFAL_API_TOKEN" "$B/$p?$Q&interval=6h&limit=100" || echo "FAIL $p"
  echo
done
