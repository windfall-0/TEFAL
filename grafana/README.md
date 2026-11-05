# TEFAL Grafana

TEFAL 보안 관제 대시보드 4종과 Grafana provisioning 설정이다.

```
grafana/
├── provisioning/
│   ├── datasources/datasources.yaml   # Prometheus, tefal-backend(Infinity). Loki·Tempo는 기존 것 사용
│   └── dashboards/dashboards.yaml     # TEFAL 폴더로 대시보드 자동 로드
├── dashboards/
│   ├── 01-overview.json       # ① 운영 현황 (uid: tefal-overview)
│   ├── 02-incident.json       # ② 사건 상세 + AI 해석 (uid: tefal-incident)
│   ├── 03-threat-intel.json   # ③ 위협 인텔리전스 (uid: tefal-ti)
│   └── 04-infra.json          # ④ 인프라 (uid: tefal-infra)
├── tools/build_dashboards.py  # 대시보드 JSON 생성기 (JSON을 직접 고치지 말고 이것을 고친다)
├── BACKEND_API.md             # tefal-backend(Python API) 요구사항
└── README.md
```

## 요구사항

| 항목 | 버전 / 비고 |
|---|---|
| Grafana | 10.4 이상 (11.x 권장) |
| 플러그인 | `yesoreyeram-infinity-datasource` (2.x), `marcusolsson-dynamictext-panel` (Business Text, AI 해석 패널) |
| Prometheus | kube-prometheus-stack (`http://kube-prometheus-stack-prometheus.monitoring:9090`). 데이터소스 uid `prometheus` |
| Loki | 기존 데이터소스 uid `P8E80F9AEF21F6940`. Tetragon 로그 `{namespace="kube-system", container="export-stdout"}` |
| Tempo | 기존 데이터소스 uid `tempo-ds`. 사건 1건 = trace 1개 (span 속성은 `BACKEND_API.md` 4장) |
| tefal-backend | `BACKEND_API.md` 참고 |

## 설치 (Helm `grafana/grafana` 차트 기준)

```bash
# 1) 대시보드 ConfigMap
kubectl -n monitoring create configmap tefal-dashboards \
  --from-file=grafana/dashboards/ --dry-run=client -o yaml | kubectl apply -f -

# 2) provisioning ConfigMap
kubectl -n monitoring create configmap tefal-grafana-provisioning \
  --from-file=datasources.yaml=grafana/provisioning/datasources/datasources.yaml \
  --from-file=dashboards.yaml=grafana/provisioning/dashboards/dashboards.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# 3) backend 토큰 Secret
kubectl -n monitoring create secret generic tefal-backend-token \
  --from-literal=TEFAL_API_TOKEN='<토큰>'
```

`values.yaml`

```yaml
plugins:
  - yesoreyeram-infinity-datasource
  - marcusolsson-dynamictext-panel

envFromSecret: tefal-backend-token          # $TEFAL_API_TOKEN

extraConfigmapMounts:
  - name: tefal-datasources
    configMap: tefal-grafana-provisioning
    subPath: datasources.yaml
    mountPath: /etc/grafana/provisioning/datasources/tefal.yaml
    readOnly: true
  - name: tefal-dashboard-provider
    configMap: tefal-grafana-provisioning
    subPath: dashboards.yaml
    mountPath: /etc/grafana/provisioning/dashboards/tefal.yaml
    readOnly: true
  - name: tefal-dashboards
    configMap: tefal-dashboards
    mountPath: /var/lib/grafana/dashboards/tefal
    readOnly: true

grafana.ini:
  users:
    viewers_can_edit: false
    default_theme: light            # 화이트 모드 (dark / light / system)
  auth.anonymous:
    enabled: false
```

kube-prometheus-stack의 sidecar를 쓰면 대시보드 ConfigMap에 `grafana_dashboard: "1"` 라벨만 붙이면 된다.

## 환경별로 수정할 값

| 위치 | 값 | 기본값 |
|---|---|---|
| `datasources.yaml` | Prometheus `url` | `http://kube-prometheus-stack-prometheus.monitoring:9090` |
| 모든 대시보드 · 데이터소스 uid | Loki, Tempo | `P8E80F9AEF21F6940`, `tempo-ds` (실제 환경 값) |
| 모든 대시보드 · 상수 변수 | `hubble_url` | `http://192.168.0.200:31235`. Cilium Helm 값은 건드리지 않고 별도 Service `kube-system/hubble-ui-nodeport`(NodePort 31235)로 노출했다. 인증이 없으니 내부망에서만 쓴다 |
| 모든 대시보드 · 상수 변수 | `headlamp_url` | `http://192.168.0.200:31240`. Helm `headlamp/headlamp`(ns `headlamp`, worker2 고정). 차트 기본 cluster-admin 바인딩은 끄고 로그인은 `headlamp/tefal-operator` 토큰으로 한다. 권한: 클러스터 namespaces·nodes 조회, `vuln-lab` 조회(secret 제외) + pod 삭제·patch, deployment patch(재시작), NetworkPolicy·CiliumNetworkPolicy 편집 |
| `02-incident.json` · 상수 변수 | `loki_selector` | `{namespace="kube-system", container="export-stdout"}` |
| `04-infra.json` · 상수 변수 | `watch_ns` | `vuln-lab` |
| `01-overview.json` · 수집 상태 패널 | DaemonSet·job 이름 정규식 | `.*tetragon.*`, `.*falco.*`, `.*(alloy\|loki\|tempo).*` |

## 대시보드 사이 이동

- 상단 링크(운영 현황 · 사건 상세 · 위협 인텔리전스 · 인프라 · Hubble UI ↗ · Headlamp ↗)가 탭 역할을 한다.
- 사건 큐의 **단계**는 Sigma level(Critical · High · Medium · Low · Info)이다. 상단 필터 `단계`로 거를 수 있다. 매칭 기준은 `BACKEND_API.md` 4.8.
- 사건 큐의 **상태**는 차단됨 · 미차단 · 판정 중이다. 판정 중은 Falco 경보 뒤 Tetragon 결과를 기다리는 사건이다.
- ① 상단 숫자를 누르면 관련 패널이 크게 열린다(필터·시간 범위 유지).
  - 미차단 → 사건 큐(상태 = 미차단)
  - 차단 → 시간대별 사건 그래프
  - 공격받은 워크로드 → 워크로드별 막대그래프
- 사건 큐에서 **아무 칸이나** 누르면 ② 사건 상세가 `trace_id`와 사건 시각 ±5분 범위로 열린다. **트레이스** 칸도 같다.
- **출발지 IP** 칸을 누르면 사건 상세와 ③ 위협 인텔리전스(해당 IP) 중에서 고른다. 출발지를 모르면 `확인 불가 (이유)`가 회색으로 보인다.
- ② 사건은 상단 드롭다운(최근 50건, 최신순)에서 고른다. 상단 "사건 상세" 버튼으로 들어오면 가장 최근 사건이 자동으로 선택되고 시간 범위는 최근 24시간이다.
  드롭다운으로 사건을 바꾸면 시간 범위는 그대로라, 사건 요약의 **이 사건 시각으로 맞추기 (±5분)** 링크로 다시 연다(원본 로그가 사건 시각 범위를 쓴다).
- ② Tempo Explore는 Trace View 패널의 링크로 연다.
- ② AI 해석은 화면을 열 때 저장된 결과만 보여 준다. **[AI 분석 요청]**·**[다시 분석]** 버튼을 눌러야 Gemini를 부른다.

## 대시보드 수정

대시보드 JSON은 생성기로 만든다. 저장소 루트에서:

```bash
PYTHONIOENCODING=utf-8 python grafana/tools/build_dashboards.py grafana/dashboards
```

실제 클러스터 반영은 `deploy/README.md`의 "대시보드 갱신"을 따른다.

## 알아 둘 동작

- **Trace View 쿼리는 `queryType: "traceql"`에 trace ID만 넣는다.** Grafana 화면(브라우저)의 Tempo 데이터소스는
  `queryType: "traceId"`를 실행하지 않아 패널이 계속 로딩된다. Grafana 서버 API(`/api/ds/query`)는 `traceId`를 받아 주므로
  서버 쪽 점검만으로는 이 문제가 보이지 않는다. Trace View 패널의 "Tempo Explore에서 열기" 링크도 같은 이유로 `traceql`이다.
- **Trace View 패널만 조회 범위가 최근 7일로 고정**되어 있다(`timeFrom: 7d`). Grafana는 trace ID 조회에도 대시보드 시간 범위를 붙이는데,
  늦게 기록된 trace(백엔드 재시작·사건 DB 재생성으로 지난 사건을 다시 기록한 경우)는 사건 시각 범위로는 Tempo에서 찾지 못한다.
- **원본 로그 필터**는 `` |= `"exec_id":"${exec_id}"` ``다. process·parent의 exec_id와 parent_exec_id에 모두 맞고,
  사건을 고르지 않아 값이 비면 아무 줄에도 맞지 않는다(전체 로그가 쏟아지지 않음).

## 참고

- 화면 시안과 픽셀 단위로 같지는 않다. 행 배경 강조, 버튼 같은 일부 표현은 Grafana 기본 패널의 기능 범위 안에서 비슷하게 맞췄다.
- 대시보드는 `allowUiUpdates: false`로 조회 전용이다. 수정은 이 저장소의 JSON을 바꾸고 ConfigMap을 다시 적용한다.
