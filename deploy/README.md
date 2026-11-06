# TEFAL 배포 (192.168.0.200 클러스터)

실제 클러스터에 TEFAL 대시보드와 tefal-backend를 올리는 절차다. 명령은 master(`ubuntu@192.168.0.200`)에서 실행한다.
비밀값(토큰, 비밀번호)은 이 저장소에 넣지 않는다.

```
deploy/
├── grafana/
│   ├── tefal-values.yaml        # Grafana helm 추가 values (데이터소스 4개, TEFAL 폴더 provisioning)
│   └── servicemonitors.yaml     # Alloy·Loki·Tempo ServiceMonitor (① 수집 상태 패널)
├── backend/gen_backend.py       # tefal-backend 매니페스트 생성기 (빌드 없이 실행)
├── falco/webhook-values.example.yaml   # Falcosidekick → 백엔드 webhook (토큰 자리표시자)
└── checks/                      # 읽기 전용 점검 스크립트
```

## 현재 구성 (2026-11-04)

| 대상 | 내용 |
|---|---|
| Grafana | `grafana/grafana` 10.5.15, release `grafana`(monitoring), NodePort 30300. TEFAL 폴더에 대시보드 4개 |
| 데이터소스 | Loki `P8E80F9AEF21F6940`, Tempo `tempo-ds`, Prometheus `prometheus`, tefal-backend(Infinity) |
| tefal-backend | monitoring, k8s-worker2 고정, `python:3.12.8-slim` + initContainer `uv sync`, 코드는 ConfigMap |
| Falco | release `falco`(falco), chart 9.2.1, revision 4에서 webhook 추가 |

## 1. Grafana

사전 조건: monitoring namespace에 Secret `tefal-backend-token`(`TEFAL_API_TOKEN`), PVC에 Infinity·Business Text 플러그인 설치.

```bash
# 대시보드 ConfigMap (저장소의 grafana/dashboards/*.json)
# 256KB를 넘어 apply의 last-applied 주석 한도를 넘는다 → 처음은 create, 이후는 replace
kubectl create configmap tefal-dashboards -n monitoring --from-file=dashboards/ --dry-run=client -o yaml \
  | kubectl label --local -f - app.kubernetes.io/part-of=tefal -o yaml | kubectl create -f -

# values 적용 (datasources 목록은 통째로 바뀌므로 기존 Loki·Tempo 정의가 tefal-values.yaml에 들어 있다)
helm upgrade grafana grafana/grafana -n monitoring --version 10.5.15 --reuse-values -f tefal-values.yaml --wait

kubectl apply -f servicemonitors.yaml
```

### 대시보드 갱신

```bash
# 로컬(저장소 루트): JSON 다시 생성
PYTHONIOENCODING=utf-8 python grafana/tools/build_dashboards.py grafana/dashboards
# master: ConfigMap 교체. Grafana가 1~2분 안에 다시 읽는다(열린 화면은 새로고침)
kubectl create configmap tefal-dashboards -n monitoring --from-file=dashboards/ --dry-run=client -o yaml \
  | kubectl label --local -f - app.kubernetes.io/part-of=tefal -o yaml | kubectl replace -f -
```

## 2. tefal-backend

```bash
# 로컬(저장소 루트): 매니페스트 생성 → deploy/backend/out/
python deploy/backend/gen_backend.py tefal-backend deploy/backend/out
#   10-code-configmap.json  코드 (app/**/*.py, pyproject.toml, uv.lock, allowlist.yaml)
#   15-sigma-configmap.json 경고 단계 매칭 표 (tefal-backend/config/sigma_levels.yaml)
#   20-backend.json         ServiceAccount·RBAC, PVC, Deployment, Service, ServiceMonitor, CiliumNetworkPolicy
```

```bash
# master: 토큰 Secret (처음 한 번). 값은 출력하지 않는다
kubectl create secret generic tefal-backend-token -n monitoring \
  --from-literal=TEFAL_API_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=FALCO_WEBHOOK_TOKEN="$(openssl rand -hex 32)"

kubectl apply   -f 15-sigma-configmap.json
kubectl replace -f 10-code-configmap.json     # 240KB라 apply의 last-applied 주석 한도를 넘는다 → replace
kubectl apply   -f 20-backend.json
kubectl rollout restart deploy/tefal-backend -n monitoring   # 코드만 바뀐 경우
```

- 컨테이너 이름은 `tefal-backend`다. 사건 요약 줄이 Loki에 `{namespace="monitoring", container="tefal-backend"}`로 들어간다.
- 첫 기동 시 `COLLECT_BACKFILL_HOURS=168`(7일) 만큼 Tetragon 로그를 읽어 사건을 만든다.
- `20-backend.json`에는 ④ 인프라용 읽기 전용 권한이 들어 있다. 권한 부여이므로 적용 전에 범위를 확인한다.
  - ClusterRole `tefal-backend-read`: pods·nodes·DS/Deploy/STS·TracingPolicy(Namespaced)·CNP·CCNP `get/list`
  - Role `falco/tefal-backend-falco-rules`: ConfigMap `falco-rules` `get`
  - 확인: `kubectl auth can-i list pods --as=system:serviceaccount:monitoring:tefal-backend` → yes, `get secrets`·`list configmaps`·`create pods`·`create pods/exec` → no

### 5단계 키와 GeoLite DB (처음 한 번)

```bash
# API 키: 기존 Secret에 더한다. 값은 셸에서 직접 넣고 출력하지 않는다 ('EOF'로 $ 확장 막기)
kubectl -n monitoring patch secret tefal-backend-token --type merge -p "$(cat <<'EOF'
{"stringData": {"ABUSEIPDB_API_KEY": "...", "VIRUSTOTAL_API_KEY": "...", "GEMINI_API_KEY": "..."}}
EOF
)"
# GeoLite2 City·ASN mmdb: 수십 MB라 Secret·ConfigMap 대신 백엔드 PVC(/data)에 둔다
P=$(kubectl -n monitoring get pod -l app.kubernetes.io/name=tefal-backend -o jsonpath="{.items[0].metadata.name}")
kubectl -n monitoring cp GeoLite2-City.mmdb $P:/data/GeoLite2-City.mmdb -c tefal-backend
kubectl -n monitoring cp GeoLite2-ASN.mmdb  $P:/data/GeoLite2-ASN.mmdb  -c tefal-backend
kubectl rollout restart deploy/tefal-backend -n monitoring
```

- 키 이름만 확인: `kubectl -n monitoring get secret tefal-backend-token -o jsonpath='{.data}' | grep -o '"[A-Z_]*"'`
- Gemini 모델은 `gen_backend.py`의 `GEMINI_MODEL`.
- ipinfo.io 토큰(선택, 무료 플랜)은 나중에 같은 방식으로 더한다. 없으면 IP 상세의 ipinfo 칸은 "토큰 추가 전"으로 비어 있다:
  `kubectl -n monitoring patch secret tefal-backend-token --type merge -p "$(cat <<'EOF'` / `{"stringData": {"IPINFO_TOKEN": "..."}}` / `EOF` / `)"` 뒤 `kubectl rollout restart deploy/tefal-backend -n monitoring`

### 경고 단계 표 수정

`tefal-backend/config/sigma_levels.yaml`을 고치고 생성기를 다시 돌린 뒤 `kubectl apply -f 15-sigma-configmap.json`.
백엔드가 1분 안팎으로 다시 읽는다. **이미 만든 사건의 단계는 바뀌지 않는다** → 아래 "사건 DB 다시 만들기".
같은 표의 `mitre` 필드(사건 큐 MITRE 열)도 새 사건부터 적용된다. 지난 사건 중 MITRE가 비어 있던 것은 처음 기동할 때 한 번 채운다(`mitre_backfill_v1`).

### 사건 DB 다시 만들기

사건은 Loki 로그에서 다시 만들 수 있는 파생 데이터다. 묶기 규칙이나 단계 표를 바꾼 뒤 지난 사건에도 적용할 때 쓴다.

1. **`tefal-backend/app/incidents/correlate.py`의 `TRACE_ID_VERSION`을 올린다.** 같은 trace_id로 다시 기록하면
   Tempo에 span이 중복되어 Trace View가 깨진다(Tempo에서는 trace를 지울 수 없다).
2. 코드 ConfigMap을 다시 적용하고, 표를 지운 뒤 재시작한다.

```bash
kubectl exec -n monitoring deploy/tefal-backend -c tefal-backend -- /deps/venv/bin/python -c "
import sqlite3; c=sqlite3.connect('/data/tefal.db')
for t in ('incidents','members','falco_alerts','exported_spans','state'): c.execute(f'DROP TABLE IF EXISTS {t}')
c.commit()"
kubectl rollout restart deploy/tefal-backend -n monitoring
```

- 다시 만들면 사건 trace_id가 모두 바뀐다. 열려 있던 사건 화면은 사건 큐에서 다시 들어간다.
- **웹훅으로만 받은 Falco 사건(Falco 단독)과 사건에 붙은 Falco 경보는 다시 만들어지지 않는다**(Loki에서 다시 읽는 것은 Tetragon뿐). 계층(`layers`)처럼 지난 사건에 값만 채우면 되는 경우는 다시 만들지 말고 기동 시 채우기(`events.backfill_layers`)처럼 처리한다.
- 되돌리기용 DB 백업: `kubectl exec … python -c "import sqlite3; sqlite3.connect('/data/tefal.db').backup(sqlite3.connect('/tmp/b.db'))"` 뒤 `kubectl cp`.
- Loki의 사건 요약 줄은 다시 만들 때마다 한 번씩 더 쌓인다(링크 기능에는 영향 없음).

## 3. Falcosidekick webhook

```bash
TOKEN=$(kubectl get secret -n monitoring tefal-backend-token -o jsonpath='{.data.FALCO_WEBHOOK_TOKEN}' | base64 -d)
sed "s/<FALCO_WEBHOOK_TOKEN>/$TOKEN/" webhook-values.example.yaml > ~/tefal-grafana/falco-webhook-values.yaml; unset TOKEN
chmod 600 ~/tefal-grafana/falco-webhook-values.yaml
helm upgrade falco falcosecurity/falco -n falco --version 9.2.1 --reuse-values -f ~/tefal-grafana/falco-webhook-values.yaml --wait
```

확인: Falcosidekick에 테스트 이벤트를 보내고 로그에서 `Webhook - POST OK (202)`를 본다.

```bash
POD=$(kubectl get pod -n falco -l app.kubernetes.io/name=falcosidekick,app.kubernetes.io/component=core -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n falco pod/$POD 2801:2801 & sleep 3; curl -s -X POST http://localhost:2801/test; kill %1
kubectl logs -n falco $POD --since=1m | grep -i webhook
```

## 4. 점검 (`checks/`, 모두 읽기 전용)

| 스크립트 | 실행 | 확인 내용 |
|---|---|---|
| `probe_attack.py [시간]` | master | 최근 공격의 기준점이 모두 사건으로 묶였는지, 정책 이름, 새 사건 Trace View |
| `verify_traces.py` | master | 모든 사건의 Trace View 쿼리(Grafana, 최근 7일): 조회 성공, 중복 span, 루트 1개 |
| `probe_loki.py stats\|types\|around` | master | Tetragon 로그 구조·기준점 통계 |
| `probe_tempo.py`, `probe_beyla_match.py` | master | Beyla trace 유무, 사건별 HTTP 요청 연결 |
| `check_incidents.sh from to` | `kubectl exec -i -n monitoring deploy/grafana -c grafana -- sh -s <from> <to> < check_incidents.sh` | 사건 API 응답 |
| `check_grafana_ds.sh`, `check_detail.sh` | 위와 같음 | Grafana(Infinity) 경유 응답, 사건 상세·메트릭 |

Grafana pod 안에서 도는 스크립트는 pod 환경 변수의 토큰·admin 자격 증명을 쓰고 값을 출력하지 않는다.

## 5. 되돌리기

```bash
helm rollback grafana 8 -n monitoring                 # TEFAL 적용 전 Grafana (Secret·ConfigMap·플러그인은 남음)
kubectl delete -f servicemonitors.yaml
kubectl delete -f 20-backend.json -f 15-sigma-configmap.json -f 10-code-configmap.json
helm rollback falco 3 -n falco                        # webhook 적용 전 Falco
```
