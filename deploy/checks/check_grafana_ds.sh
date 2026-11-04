# Grafana pod 안에서 실행: 대시보드와 같은 경로(Grafana → Infinity → tefal-backend)로 질의. 자격 증명은 출력하지 않는다.
U="${GF_SECURITY_ADMIN_USER:-admin}:${GF_SECURITY_ADMIN_PASSWORD}"
for url in "/incidents/summary?from=$1&to=$2&namespace=\$__all&runtime=Java,PHP,Node&status=\$__all&level=critical,high,medium,low,informational" \
           "/incidents?from=$1&to=$2&namespace=vuln-lab&runtime=Java&status=blocked&level=informational&limit=100"; do
  body=$(cat <<EOF
{"from":"$1","to":"$2","queries":[{"refId":"A","datasource":{"type":"yesoreyeram-infinity-datasource","uid":"tefal-backend"},
 "type":"json","source":"url","parser":"backend","format":"table","url":"$url","url_options":{"method":"GET"}}]}
EOF
)
  echo "== $url" | cut -c1-60
  wget -qO- --header "Content-Type: application/json" --header "Authorization: Basic $(printf %s "$U" | base64 | tr -d '\n')" \
    --post-data "$body" http://localhost:3000/api/ds/query | head -c 700
  echo
done
