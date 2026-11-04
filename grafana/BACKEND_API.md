# tefal-backend API 요구사항

Grafana 대시보드 4종(운영 현황 · 사건 상세 · 위협 인텔리전스 · 인프라)에서 **Tempo/Loki/Prometheus만으로 만들 수 없는 데이터**를 제공하는 Python API 서버 요구사항이다.
Grafana는 **Infinity 데이터소스**(`yesoreyeram-infinity-datasource`)로 이 서버를 호출한다.

---

## 1. 역할과 범위

| 구분 | 담당 |
|---|---|
| 사건(incident) 생성 | Tetragon 차단(Sigkill·Override)과 Falco 경보를 기준점으로 관련 이벤트를 묶고 `trace_id`를 부여 (4장) |
| 사건(incident) 집계 | 생성한 사건을 목록·요약·통계로 제공 |
| 위협 인텔리전스(TI) | AbuseIPDB · VirusTotal · GeoIP(MaxMind) 조회, 캐시, 한도 관리 |
| AI 해석 | 사건 근거 로그를 Gemini에 넘겨 요약·판단·대응 가이드 생성, 캐시 |
| 정책 통계 | 정책별 히트 수, 오탐 의심 판정 |
| 인프라 보조 | Prometheus로 얻을 수 없는 K8s CRD 수, 워크로드별 정책 매핑, Hubble 차단 흐름 |

**범위 밖 (Grafana가 직접 조회):**
- Trace View → Tempo
- 원본 로그 → Loki
- 노드 CPU/메모리, 노드·pod 수, 수집 상태 → Prometheus

**원칙**
- 조회 전용이다. 격리·재시작 같은 클러스터 조작 API는 만들지 않는다(조작은 Headlamp가 맡는다).
- K8s 접근은 `get/list/watch` 권한만 가진 ServiceAccount로 한다.

---

## 2. 기술 스택 (권장)

| 항목 | 선택 |
|---|---|
| 프레임워크 | FastAPI + Uvicorn |
| HTTP 클라이언트 | httpx (async), 외부 호출 타임아웃 5초 |
| 캐시/저장 | SQLite(단일 Pod) 또는 Redis(확장 시) |
| GeoIP | MaxMind GeoLite2-City / GeoLite2-ASN `.mmdb`를 로컬 파일로 읽음 (`geoip2`) |
| K8s | `kubernetes` 공식 클라이언트, in-cluster config |
| Hubble | Hubble Relay gRPC (`hubble-relay.kube-system:80`) |
| 이벤트 수신 | Loki tail API(WebSocket, `websockets`) + Falcosidekick webhook |
| trace 기록 | OTLP/HTTP JSON → Tempo `:4318/v1/traces` |
| AI | Google Gemini API (`google-genai`) |
| 배포 | `Deployment` 1 replica, `Service tefal-backend` (port 8000), namespace `monitoring` |

---

## 3. 공통 규약

### 3.1 Infinity 호환 응답
- 응답은 **JSON 배열 또는 평탄한 객체**로 준다. 중첩이 깊으면 Grafana에서 컬럼으로 뽑기 어렵다.
- 시각은 **epoch ms(정수)** 와 표시용 문자열(`HH:MM:SS`)을 함께 준다.
- 키 이름은 `snake_case`로 쓰고, 표 컬럼명은 Grafana에서 바꾼다.

### 3.2 공통 쿼리 파라미터
Grafana 변수를 그대로 넘길 수 있게 한다.

| 파라미터 | 예 | 설명 |
|---|---|---|
| `from`, `to` | `${__from}`, `${__to}` | epoch ms 시간 범위 |
| `namespace` | `web` / `All` | `All`이면 필터 없음 |
| `runtime` | `java,php,node` | 쉼표 구분, 다중 선택 |
| `status` | `blocked` / `unblocked` / `pending` / `All` | 사건 상태 |
| `level` | `critical,high` / `All` | Sigma level. 쉼표 구분, 다중 선택 |

### 3.3 인증
- `Authorization: Bearer <TEFAL_API_TOKEN>` 헤더로 인증한다. Infinity 데이터소스 설정에 토큰을 넣는다.
- `/healthz`, `/metrics`는 인증 없이 연다(클러스터 내부에서만 접근).

### 3.4 오류
- `4xx/5xx` + `{"error": "...", "detail": "..."}`
- 외부 API가 실패하면 캐시된 값을 주고 `"stale": true`를 붙인다. 캐시도 없으면 해당 필드를 `null`로 준다(패널이 깨지지 않게).

---

## 4. 사건 생성과 모델

`trace_id 1개 = 사건 1건`. **최종 결과(차단 · Override · Falco 경보)를 기준점으로 trace_id를 부여**하고, 기준점 이전의 관련 이벤트를 거슬러 올라가 하나의 사건으로 묶는다. 사건 생성은 백엔드가 맡는다. Alloy의 `loki.process`는 줄 단위 처리라서 이벤트 사이를 연결할 상태를 가질 수 없기 때문이다.

### 4.1 흐름

```
Tetragon ─(stdout)→ Alloy → Loki ──tail──┐
Falco ─→ Falcosidekick ─(webhook)────────┼→ tefal-backend
                                          │   ① 기준점 감지
                                          │   ② Loki 역조회로 관련 이벤트 수집
                                          │   ③ trace_id 부여, 하나의 사건으로 묶기
                                          ├→ Tempo   (계층별 span + Beyla HTTP trace span link)
                                          ├→ SQLite  (사건 목록 → 대시보드 API)
                                          └→ Loki    (사건 요약 1줄, trace_id 포함 · stdout → Alloy)
```

### 4.2 기준점 (anchor)

| 종류 | 조건 | 수신 경로 | 사건 상태 |
|---|---|---|---|
| Tetragon 차단 | `process_lsm` / `process_kprobe` / `process_uprobe`의 `action`이 `KPROBE_ACTION_SIGKILL` 또는 `KPROBE_ACTION_OVERRIDE` | Loki tail `{namespace="kube-system", container="export-stdout"}` | `blocked` |
| Falco 경보 | Falcosidekick webhook으로 받은 경보 중 `priority` ≥ `FALCO_MIN_PRIORITY`이고 대상 namespace가 `WATCH_NAMESPACES`에 속함 | `POST /ingest/falco` (5.1) | 우선 `pending`, 이후 `blocked` 또는 `unblocked` (4.4) |

- 실제 클러스터의 차단 정책 `log4shell-bpflsm-block`은 `Override`다. Override는 프로세스를 죽이지 않고 exec를 EPERM으로 실패시키므로 `process_exit signal=SIGKILL`이 남지 않는다. 그래서 **`process_exit`를 기준점으로 쓰지 않는다.**
- tail 연결이 끊기면 마지막으로 처리한 시각부터 `query_range`로 다시 읽어 빈 구간을 메운다(5초 겹치게 읽고 중복은 버린다).

### 4.3 관련 이벤트 수집 (역조회)

1. **계보 확보:** 기준점 이벤트의 `process.exec_id`, `parent.exec_id`, `ancestors[].exec_id`를 모은다. 컨테이너 init 프로세스(`in_init_tree=true`이면서 pid 1) 직전까지만 올라간다. 그 위는 모든 사건에 공통이라 묶지 않는다.
   - Tetragon에서 `ancestors` 옵션을 켜야 한다(9장 1번). 켜지 못하면 `parent_exec_id`를 따라 Loki를 단계별로 다시 조회한다(최대 `CORRELATE_MAX_DEPTH` 단계).
2. **이벤트 조회:** 기준점 시각에서 `CORRELATE_LOOKBACK_SEC`(기본 60초) 전부터 기준점 직후 2초까지, 위 exec_id가 `process.exec_id`나 `parent.exec_id`에 들어 있는 Tetragon 이벤트를 Loki에서 가져온다.
3. **Falco 경보 연결:** 같은 컨테이너 ID에서, `proc.pid`나 `proc.ppid`가 계보의 pid와 같고, 같은 시간 범위에 있는 경보를 붙인다.
4. **Beyla HTTP trace 연결:** 같은 pod의 Beyla span 중에서 첫 기준점 시각을 시작~끝 사이에 포함하는 HTTP 서버 span을 찾아 **span link**로 건다. trace_id는 덮어쓰지 않는다.
   - **시각 여유 ±0.5초:** Beyla와 Tetragon 시각은 수 ms 어긋난다(실측: 기준점이 요청 시작보다 3ms 앞선 경우). span 앞뒤 0.5초 안이면 후보로 보고, 감싸는 span을 우선한다.
   - **조회 범위:** 기준점 60초 전 ~ 2초 후(TraceQL `{ resource.k8s.pod.name = "<pod>" && kind = server }`). 범위를 넓히면 요청이 많은 앱에서 결과 한도에 걸려 맞는 span이 잘린다.
   - **역조회 하한:** 요청이 연결되면 그 요청 시작 1초 전보다 이른 이벤트는 묶지 않는다. 앞선 다른 요청의 이벤트이기 때문이다.
   - Beyla span에는 pid 속성이 없어 PHP도 시각으로만 맞춘다.
   - PHP(apache prefork)는 요청마다 워커 pid가 달라서 pid까지 맞추면 확실하다.
   - Java·Node는 한 프로세스가 요청을 동시에 처리하므로 시각으로 추정한다. 후보가 2개 이상이면 시작 시각이 가장 가까운 것을 고르고 `tefal.link_confidence=low`를 붙인다.

### 4.4 묶기 규칙

| 규칙 | 내용 | 설정 |
|---|---|---|
| 연속 차단 병합 | 같은 부모 exec_id 아래에서 `CORRELATE_MERGE_SEC` 안에 기준점이 또 나오면 새 사건을 만들지 않고 기존 사건에 합친다. 공격자가 명령을 연달아 시도하는 경우다 | 기본 10초 |
| Falco 선행 경보 | Falco 경보로 `pending` 사건을 만든다. `FALCO_WAIT_SEC` 안에 같은 계보에서 차단 기준점이 오면 그 사건에 합쳐 `blocked`로 바꾼다. 시간이 지나도 차단이 없으면 `unblocked`로 확정한다 | 기본 30초 |
| 같은 요청 병합 | 같은 Beyla HTTP 요청에 연결된 기준점은 병합 간격을 넘어도 한 사건이다(한 요청 = 한 사건) | |
| Falco 후행 경보 | 차단 사건이 확정된 뒤 `FALCO_WAIT_SEC` 안에 같은 계보의 경보가 오면 그 사건에 붙인다 | 기본 30초 |
| 사건 확정 | 마지막 이벤트 이후 `CORRELATE_MERGE_SEC`가 지나면 확정하고 Tempo·Loki에 기록한다. 확정 전에는 대시보드에 `pending`으로 보인다 | |

- **`pending` 표시:** 사건 큐와 상태 필터에서 "판정 중"으로 보인다. 요약 카드·막대·시계열에서는 미차단 쪽에 넣어 센다(놓치지 않는 쪽을 택한다).

### 4.5 trace_id

- `trace_id = sha256(node + "|" + anchor_exec_id + "|" + anchor_time_ns)`의 앞 32자리 hex.
  - 같은 기준점이면 항상 같은 ID가 나와서, 백엔드가 재시작해 같은 구간을 다시 읽어도 사건이 중복되지 않는다.
  - Falco가 기준점이면 `anchor_exec_id` 자리에 Falco 경보 UUID를 쓴다. 나중에 차단과 병합되면 **먼저 만든 ID를 유지**한다.
- 32자리가 모두 0이면 W3C 규격상 무효이므로 마지막 자리를 `1`로 바꾼다.
- 실제 키는 `v<TRACE_ID_VERSION>|node|anchor_exec_id|anchor_time_ns`다(`app/incidents/correlate.py`). Tempo에 잘못 기록된 trace는 지울 수 없으므로, 사건 DB를 다시 만들 때는 버전을 올려 새 ID를 쓴다. 같은 ID로 다시 기록하면 span이 중복되어 Trace View가 깨진다.

### 4.6 결과 기록

| 대상 | 내용 |
|---|---|
| Tempo | 계층별 span: 루트 `incident <pod>` 아래 프로세스마다 `proc <binary>`(exec~exit), 그 아래 `app·uprobe` / `proc`(kprobe) / `kernel·LSM` 이벤트 span, `falco` span. 기준점 span은 `status=ERROR`. Beyla HTTP span은 루트 span의 span link로 연결. OTLP/HTTP JSON으로 보낸다(`TEMPO_OTLP_URL`). **한 번 보낸 span은 다시 보내지 않는다**(`exported_spans` 표). Tempo는 같은 span ID를 합쳐 주지 않아서, 다시 보내면 중복 span이 생겨 Grafana Trace View가 그려지지 않는다 |
| SQLite | 아래 사건 모델 + `members` 테이블(`trace_id`, `exec_id`, `event_time_ns`, `event_type`) |
| Loki | 사건 요약 1줄. 백엔드 stdout(logger `tefal.incident`)에 남기고 Alloy가 수집한다. 조회 `{namespace="monitoring", container="tefal-backend"} \|= "tefal_incident"`, 내용 `tefal_incident trace_id=<id> status=<status> level=<level> pod=<pod> policy=<policy>`. 사건을 만들거나 상태가 바뀔 때마다 1줄씩 남는다. 기존 Grafana Loki 데이터소스의 derived field(`trace_id[=:"\s]+([a-f0-9]{32})`)가 이 값을 Tempo 링크로 바꿔 준다 |

- 이미 Loki에 들어간 Tetragon 로그에는 나중에 trace_id를 써 넣을 수 없다. 그래서 대시보드 ② 원본 로그는 **사건에 묶인 exec_id들로** 거른다. 사건 모델의 `exec_id`(기준점 프로세스)와 `parent_exec_id`(직계 부모)를 이 용도로 준다.

### 4.7 사건 모델

```json
{
  "trace_id": "4f9a2e...c21b",
  "start_ms": 1762146750412,      // 묶인 이벤트 중 가장 이른 시각
  "anchor_ms": 1762146750413,     // 기준점 시각
  "time": "14:12:30",
  "status": "blocked",            // blocked | unblocked | pending
  "status_label": "차단됨",        // 차단됨 | 미차단 | 판정 중
  "level": "high",                // Sigma level: critical | high | medium | low | informational (4.8)
  "level_source": "tetragon:log4shell-bpflsm-block",   // 단계를 정한 룰
  "action": "Override",           // Sigkill | Override | Detected
  "detected_by": "tetragon",      // tetragon | falco | tetragon+falco
  "namespace": "vuln-lab",
  "pod": "log4shell-559b65696c-mpvhl",
  "workload": "vuln-lab / log4shell-559b65696c-mpvhl",
  "node": "k8s-worker1",
  "runtime": "Java",              // Java | PHP | Node
  "runtime_detail": "Java 8 (Spring Boot)",
  "summary": "forkAndExec → /bin/bash -i (리버스 셸)",
  "mitre": ["T1059.004"],
  "src_ip": "198.51.100.77",
  "exec_id": "azhzLXdvcmtlcjE6...",
  "parent_exec_id": "azhzLXdvcmtlcjE6...",
  "policy": "log4shell-bpflsm-block",
  "member_count": 5,
  "falco_rules": ["Shell Spawned in Vuln Lab"],
  "beyla_trace_id": "867bbfd3b56f437005157d86c60ef2c8",   // 없으면 null
  "beyla_link_confidence": "high",                        // high | low | null

  // ── 대시보드 표시용 (Infinity가 배열·계산을 다루기 어려워 서버에서 만든다)
  "status_text": "차단됨 · Override",
  "time_text": "14:12:30.412",
  "mitre_text": "T1505.003 · T1059.004",
  "window_from_ms": 1762146450412,   // start_ms - 5분 (사건 상세 시간 범위)
  "window_to_ms": 1762147050412      // start_ms + 5분
}
```

- `summary`, `mitre`: 정책 이름·훅·바이너리 조합으로 만드는 규칙 표(`summary_rules.yaml`)에서 고른다. 맞는 규칙이 없으면 기준점의 `binary + arguments`를 그대로 쓴다.
- `src_ip`: Beyla span의 `client.address`를 우선 쓴다. 없으면 Falco 경보의 `fd.rip`을 쓴다.

### 4.8 경고 단계 (Sigma level)

- 단계는 Sigma 룰의 `level` 5단계를 쓴다: `critical` > `high` > `medium` > `low` > `informational`.
- 매칭 표 `sigma_levels.yaml`에서 사건에 묶인 이벤트마다 단계를 찾는다. 키는 Tetragon `policy_name`과 Falco `rule`이다.
- **매칭 표:** `tefal-backend/config/sigma_levels.yaml`(최종 운영 정책 15개 기준, 2026-11-04). 클러스터에는 ConfigMap `tefal-sigma-levels`로 `/config`에 마운트한다. Cilium 정책(`log4shell-egress-block`)은 Tetragon 로그에 없어 `cilium:` 절에 기록만 하고 아직 읽지 않는다.
- 단계가 같으면 차단(기준점) 정책이 `level_source`가 된다.
  ```yaml
  # 형식 예시 (내용은 추후 제공)
  tetragon:
    log4shell-bpflsm-block: { level: high, sigma: "<Sigma 룰 id 또는 제목>" }
  falco:
    "Shell Spawned in Vuln Lab": { level: high, sigma: "<Sigma 룰 id 또는 제목>" }
  ```
- **사건 단계 = 묶인 이벤트 단계 중 가장 높은 값.** `level_source`에는 그 단계를 정한 룰을 `tetragon:<policy>` 또는 `falco:<rule>`로 적는다.
- 표에 없는 룰은 아래 기본값을 쓴다.
  - Falco: `priority`로 정한다. Emergency·Alert·Critical → `critical`, Error → `high`, Warning → `medium`, Notice → `low`, 그 외 → `informational`
  - Tetragon: `informational`
- 표는 백엔드 시작 시 읽고, 파일이 바뀌면 다시 읽는다(ConfigMap 마운트). 이미 만든 사건의 단계는 바꾸지 않는다.

**Tempo span 속성 (백엔드가 기록)**
`k8s.namespace`, `k8s.pod`, `tefal.runtime`, `tefal.layer`(app·uprobe / proc / kernel·LSM / falco), `tefal.action`, `tefal.policy`, `tefal.mitre`, `tefal.summary`, `net.src_ip`, `tetragon.exec_id`, `tetragon.parent_exec_id`, `tefal.link_confidence`

---

## 5. 엔드포인트

### 5.1 사건 (① 운영 현황, ② 사건 상세)

#### `GET /incidents`
사건 큐 표. 미차단 먼저, 그다음 최신순으로 정렬한다.
- 파라미터: `from`, `to`, `namespace`, `runtime`, `status`, `level`, `limit`(기본 100)
- 다른 `/incidents/*` 집계 API도 같은 필터(`namespace`, `runtime`, `status`, `level`)를 받는다.
- 응답: 사건 모델 배열

#### `GET /incidents/summary`
상단 Stat 카드 3개와 경고 단계별 건수.
```json
{
  "unblocked_count": 2,
  "unblocked_last_time": "14:32",
  "blocked_count": 5,
  "attacked_workloads": 3,
  "total_workloads": 7,
  "level_critical_count": 1,
  "level_high_count": 3,
  "level_medium_count": 2,
  "level_low_count": 1,
  "level_informational_count": 0
}
```
`total_workloads`는 `namespace` 필터에 걸리는 Running pod 수다(K8s API 기준).
`level_*_count`는 사건 단위(사건마다 가장 높은 단계 하나)다. 대시보드의 단계별 카드는 이 값 대신 로그 기준 `/policies/levels`(5.2)를 쓴다. 사건은 대부분 LSM 차단(critical)으로 끝나서 사건 단위로는 critical만 남기 때문이다.

#### `GET /incidents/by-workload`
"워크로드별 사건 · 패치·격리 우선순위" 막대. 미차단 수가 많은 순, 같으면 총 건수가 많은 순으로 정렬한다.
```json
[{ "pod": "log4shell-5b7d", "blocked": 1, "unblocked": 1, "total": 2,
   "label": "2건 · 미차단 1" }]
```

#### `GET /incidents/timeseries`
"시간대별 사건" 누적 막대.
- 파라미터: `interval`(기본 `5m`)
- 응답: 빈 구간도 0으로 채운다.
```json
[{ "time_ms": 1762145400000, "blocked": 1, "unblocked": 0 }]
```

#### `GET /incidents/{trace_id}`
② 상단 요약 줄. 사건 모델 1건을 준다. 없으면 `404`.

#### `POST /ingest/falco`
Falcosidekick webhook 수신(4.2). Falcosidekick `webhook.address`를 `http://tefal-backend.monitoring.svc:8000/ingest/falco`로 설정한다.
- 인증: `Authorization: Bearer <FALCO_WEBHOOK_TOKEN>` (Falcosidekick `webhook.customHeaders`로 넣는다). Grafana용 토큰과 분리한다.
- 본문: Falcosidekick 기본 JSON(`uuid`, `rule`, `priority`, `time`, `output_fields`)
- 응답: `202 {"trace_id": "...", "status": "pending"}`. 대상 밖 경보는 `202 {"ignored": true}`
- 같은 `uuid`가 다시 오면 무시한다(Falcosidekick 재전송 대비).

---

### 5.2 정책 (① 정책 상태)

#### `GET /policies/stats`
- 파라미터: `from`, `to`, `namespace`(All이면 전체)
```json
[{
  "policy": "php2shell-lsm-bprmcheck-block",
  "tag": "critical",               // 경고 단계 (4.8, sigma_levels.yaml)
  "layer": "커널 (LSM)",            // 커널 (LSM) | 커널 (kprobe) | 커널 (tracepoint) | 앱 (uprobe) | Falco | Falco (커스텀)
  "action": "차단 (Override)",      // 차단 (Override) | 차단 (Sigkill) | 기록 | 탐지
  "hits": 59,
  "false_positive_suspect": null,
  "fp_note": null
}]
```

구현 (`app/policies.py`, `app/routers/policies.py`):
- 행: 클러스터의 TracingPolicy 전체(`namespace`를 주면 다른 namespace의 `TracingPolicyNamespaced` 제외) + Falco 커스텀 룰 전체 + 그 namespace에서 맞은 Falco 기본 룰. `Falco internal: ...` 자체 상태 경보는 뺀다. 지금 클러스터에 없는 옛 정책 이름은 히트가 있어도 보이지 않는다.
- `hits`: Tetragon은 Loki `count_over_time`을 `policy_name`(kprobe·uprobe·lsm·tracepoint)별로, Falco는 `{namespace="falco", container="falco"}` 로그를 `rule`별로 센다. namespace는 각각 `process.pod.namespace`, `output_fields["k8s.ns.name"]`로 거른다. 30초 캐시.
- `layer`: TracingPolicy spec에 있는 훅 종류(`lsmhooks`, `kprobes`, `tracepoints`, `uprobes`). 여러 개면 `+`로 잇는다.
- `tag`: Falco 룰은 표에 없으면 룰 정의의 `priority`로 정한다(히트가 없어도 단계가 나온다).
- **오탐 의심은 아직 판정하지 않는다** (`false_positive_suspect`, `fp_note`가 `null`). 대시보드 표에서도 칸을 뺐다. 아래 규칙은 다음 단계 안이다.

#### `GET /policies/levels`
① "경고 단계별 탐지 · 로그 기준". 파라미터: `from`, `to`, `namespace`.
```json
{ "total": 412, "level_critical_count": 153, "level_high_count": 92, "level_medium_count": 96,
  "level_low_count": 31, "level_informational_count": 40 }
```
- Tetragon·Falco 로그 한 줄을 1로 세서 정책·룰의 단계(4.8)별로 더한다. `/policies/stats`와 같은 Loki 집계(30초 캐시)를 쓴다.
- Tetragon은 **지금 클러스터에 있는 TracingPolicy의 로그만** 센다. 옛 테스트 정책(`r2s-final-*` 등)의 로그는 Loki에 남아 있어도 빼서, 지운 정책이 Info를 부풀리지 않게 한다. Falco는 모든 룰을 세고 `Falco internal: ...`만 뺀다.
- 사건 수와 단위가 다르다(공격 1번 = 로그 여러 줄). `runtime`, `status`, `level` 필터는 적용하지 않는다.

**오탐 의심 판정 규칙 (다음 단계 안)**
- 정상 워크로드(`*-normal`, `traffic-gen`) 동작에서 같은 정책이 시간 범위 안에 `FP_THRESHOLD`(기본 5)회 이상 맞으면 의심으로 본다.
- 공격 pod여도 같은 `binary+args` 패턴이 반복되면 의심으로 보고, 가장 많이 나온 패턴을 `fp_note`에 적는다.
- 허용 목록(`allowlist.yaml`)에 있는 패턴은 제외한다.

---

### 5.3 AI 해석 (② AI 해석 · 대응 가이드)

#### `GET /ai/analysis/{trace_id}`
- 캐시가 있으면 바로 준다. 없으면 생성한 뒤 준다(동기 방식, 타임아웃 30초).
- `?refresh=true`이면 캐시를 무시하고 다시 생성한다. "다시 분석" 링크가 이 주소를 쓴다.

```json
{
  "trace_id": "4f9a2e...c21b",
  "model": "gemini",
  "cached_at": "14:12:41",
  "summary": "업로드 디렉터리의 PNG 위장 PHP 파일이 실행되어 ...",
  "verdict": "공격",               // 공격 | 오탐 의심 | 판단 불가
  "risk": "높음",                  // 높음 | 중간 | 낮음
  "mitre": [{ "id": "T1505.003", "name": "웹셸" }],
  "evidence": [
    "uprobe zif_system cmd=\"id; uname -a\"",
    "exec /bin/sh parent=apache2 → Sigkill"
  ],
  "guide": [
    "업로드 경로 /hackable/uploads/의 PHP 실행 권한 제거",
    "업로드 시 확장자 + 매직바이트 + 이중 확장자 검증"
  ],
  "disclaimer": "AI가 생성한 해석입니다. 근거 로그와 대조해 확인하세요.",
  "markdown": "..."                // Text 패널용으로 위 내용을 렌더링한 문자열
}
```

**생성 규칙**
- 입력: 사건 모델 + 사건에 묶인 이벤트(`members`, 최대 50줄) + Falco 경보 + TI 요약
- Gemini에는 **구조화 출력(JSON schema)** 을 강제하고, 파싱이 실패하면 1회 재시도한다.
- `evidence`는 입력 로그에 실제로 있는 줄만 넣는다. 서버에서 원문과 대조해서 없는 줄은 버린다.
- 프롬프트에 비밀값(토큰, 환경 변수)과 사설 IP 외의 내부 정보를 넣지 않는다.
- 같은 `trace_id`의 동시 요청은 1번만 생성한다(락).
- 캐시 TTL은 기본 7일. `refresh` 요청은 분당 `AI_REFRESH_PER_MIN`(기본 5)회로 제한한다.

---

### 5.4 위협 인텔리전스 (② 출발지 IP 요약, ③ 전체)

#### `GET /ti/ips`
③ Geomap과 IP 평판 표가 함께 쓴다. 시간 범위 안 사건의 출발지 IP 중 공인 IP만 준다.
- 파라미터: `from`, `to`, `min_abuse`(기본 0)
```json
[{
  "ip": "198.51.100.23",
  "country": "NL",
  "asn": "AS[번호]",
  "isp": "[호스팅 업체]",
  "lat": 52.37, "lon": 4.89,
  "abuse_score": 87,
  "abuse_reports": 214,
  "risk_level": "high",           // high(≥75) | mid(25–74) | low(<25 / 정보 없음)
  "vt_malicious": 6,
  "vt_total": 94,
  "related_incidents": 3,
  "last_checked": "14:31",
  "asn_isp": "AS[번호] · [호스팅 업체]",   // 표시용
  "vt_text": "6 / 94"                       // 표시용
}]
```

#### `GET /ti/ip/{ip}`
② 출발지 IP 요약과 ③ 선택 IP 상세.
```json
{
  "ip": "198.51.100.23",
  "country": "NL", "asn": "AS[번호]", "isp": "[호스팅 업체]",
  "abuse_score": 87,
  "last_reported": "3시간 전",
  "usage_type": "Data Center / Hosting",
  "is_tor": false,
  "abuse_categories": ["Web App Attack", "Hacking", "Port Scan", "Brute-Force"],
  "vt_malicious": 6, "vt_suspicious": 2, "vt_harmless": 71, "vt_undetected": 15,
  "vt_total": 94,
  "cached": true,
  "country_asn": "NL · AS[번호]",                                      // 표시용
  "vt_text": "6 / 94 악성",                                            // 표시용
  "abuse_categories_text": "Web App Attack, Hacking, Port Scan, Brute-Force"  // 표시용
}
```
사설 IP면 `400 {"error": "private_ip"}`를 준다.

#### `GET /ti/summary`
③ 우측 Stat 카드.
```json
{
  "public_ip_count": 4,
  "high_risk_count": 2,
  "abuseipdb_used": 37, "abuseipdb_limit": 1000,
  "virustotal_used": 12, "virustotal_limit": 500,
  "cache_ttl_hours": 24,
  "cache_hit_rate": 0.81
}
```

#### `GET /ti/files`
③ 파일 해시 조회. 시간 범위 안 사건에서 업로드·쓰기된 파일을 준다.
- 파라미터: `from`, `to`, `ip`(선택)
```json
[{
  "path": "/hackable/uploads/cat.png.php",
  "sha256": "...",
  "vt_found": false,
  "vt_malicious": 0,
  "message": "VirusTotal에 기록이 없는 파일입니다. 시그니처로는 알 수 없었지만 Tetragon이 행위 기준으로 차단했습니다.",
  "related_trace_ids": ["4f9a2e...c21b"]
}]
```

**TI 규칙**
- **사설 IP 제외:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`, IPv6 사설/링크로컬. 외부 API로 절대 보내지 않는다.
- **캐시:** 같은 IP와 해시는 `TI_CACHE_TTL_HOURS`(기본 24시간) 동안 다시 조회하지 않는다. 적중률은 계산해서 노출한다.
- **일일 한도:** 서비스별 사용량을 UTC 날짜 기준으로 센다. 한도의 90%를 넘으면 새 조회는 멈추고 캐시만 준다.
  - AbuseIPDB 무료: `check` 1,000회/일
  - VirusTotal 공개 API: 500회/일, **4회/분** → 내부 큐로 속도를 제한한다.
- **GeoIP:** 로컬 mmdb만 쓴다(외부 호출 없음). 위경도가 없으면 Geomap에서 빠지고 표에는 남는다.
- **미리 조회(선택):** 새 사건이 생기면 백그라운드에서 TI를 미리 조회해 두면 대시보드 응답이 빨라진다.

---

### 5.5 인프라 (④)

CPU/메모리 사용률과 노드·pod 수 Stat은 Prometheus가 직접 맡는다.
표 패널(노드, 워크로드, 컴포넌트)은 여러 메트릭을 Grafana에서 조인하기 번거로워서 **백엔드가 K8s API로 한 번에 모아서 준다.**

구현 (`app/k8s.py`, `app/infra.py`, `app/routers/infra.py`):
- 새 의존성 없이 httpx로 K8s API를 부른다. pod의 ServiceAccount 토큰과 CA를 쓰고, 토큰은 60초마다 파일에서 다시 읽는다. 토큰이 없으면(로컬 실행) 인프라 API는 `503 k8s_unavailable`을 준다.
- 응답은 30초 캐시한다. K8s API가 실패하면 직전 값으로 답하고, 직전 값이 없으면 `502 k8s_error`를 준다.

#### `GET /infra/policies`
"적용된 정책 9 · 격리된 워크로드 0" 카드.
```json
{ "total": 17, "tracing_policies": 14, "tracing_block_policies": 3,
  "falco_custom_rules": 3, "isolated_workloads": 0 }
```
- `tracing_policies`: `cilium.io/v1alpha1` `TracingPolicy` + `TracingPolicyNamespaced` 개수
- `tracing_block_policies`: 그중 `matchActions`에 `Override` 또는 `Sigkill`이 있는 정책 수
- `falco_custom_rules`: Falco 커스텀 룰 ConfigMap의 `- rule:` 개수
- `isolated_workloads`: 격리용 `CiliumNetworkPolicy`(라벨 `tefal.io/isolate=true`)가 걸린 pod 수

#### `GET /infra/workloads`
"워크로드 보호 현황" 표.
- 파라미터: `namespace`(기본 `WATCH_NAMESPACES`의 첫 값)
```json
[{ "pod": "php2shell-b994795c-kj4rm", "pod_label": "php2shell-b994795c-kj4rm (PHP)", "runtime": "PHP",
   "status": "Running", "restarts": 0, "node": "k8s-worker2",
   "tetragon_policy": "차단 1 · 관찰 3",
   "tetragon_policies": ["php2shell-kprobe-execve", "..."],
   "falco": "기본 + 커스텀 3",
   "network": "" }]
```
- `pod_label`: 비교용 pod는 `(비교용)`, traffic-gen은 `(정상 트래픽)`을 붙인다(라벨 `tefal.io/role`).
- `status`: pod phase. CrashLoopBackOff 같은 컨테이너 대기 사유가 있으면 그 값을 준다.
- 매핑 기준: TracingPolicy의 `podSelector`와 CiliumNetworkPolicy의 `endpointSelector`를 pod 라벨에 맞춰 본다(`matchLabels`, `matchExpressions`, `k8s:` 접두사). 정책이 없으면 빈 문자열을 준다.
  - `TracingPolicyNamespaced`는 같은 namespace pod에만 건다.
  - `podSelector`가 없는 TracingPolicy는 Tetragon이 모든 pod에 걸지만 실제로는 uprobe 대상 바이너리로 좁혀진다. 표에서는 정책 이름 앞부분(`php2shell-...`)이 pod의 `app` 라벨과 같을 때만 그 pod의 정책으로 센다.
- `tetragon_policy`: 차단(Override·Sigkill) 정책 수와 관찰 정책 수.
- `runtime`: 사건에서 확인된 런타임 → 이미지 이름 → 라벨 순으로 정한다. DB·캐시 이미지(mariadb, mysql, postgres, redis, mongo, memcached)는 런타임을 비운다.
- `falco`: 기본 룰은 모든 컨테이너에 걸린다. 커스텀 룰 ConfigMap(`FALCO_RULES_CONFIGMAP`)에 그 namespace가 나오면 `기본 + 커스텀 N`.

#### `GET /infra/nodes`
"노드" 표.
```json
[{ "node": "k8s-node1", "ready": "true", "role": "control-plane + worker",
   "kernel": "6.x", "bpf_lsm": "true", "pods": 19 }]
```
- `ready`, `bpf_lsm`은 문자열 `"true"`/`"false"`로 준다(값 매핑용).
- `kernel`은 `node.status.nodeInfo.kernelVersion`에서 읽는다.
- `bpf_lsm`: 노드 라벨 `tefal.io/bpf-lsm`(true/false)이 있으면 그 값. 없으면 최근 7일 Tetragon `process_lsm` 이벤트가 나온 노드를 `"true"`로, 나머지는 `"unknown"`(확인 안 됨)으로 준다. LSM 정책이 걸리지 않는 노드(control-plane)는 `unknown`이 정상이다. Loki 조회는 5분 캐시한다.
- `role`: control-plane 라벨이 있고 `NoSchedule` taint가 있으면 `control-plane`, taint가 없으면 `control-plane + worker`.

#### `GET /infra/components`
"보안·관측 컴포넌트" 표.
```json
[{ "name": "Cilium", "kind": "DS", "ready": 2, "desired": 2, "ready_text": "2/2" }]
```
대상: Cilium(DS), Hubble Relay(Deploy), Tetragon(DS), Falco(DS), Falcosidekick(Deploy), Alloy(DS), Loki(STS), Tempo(STS), Prometheus(STS), Grafana(Deploy), tefal-backend(Deploy). 목록은 `app/infra.py`의 `DEFAULT_COMPONENTS`에 있다. 객체가 없거나 읽을 수 없으면 `ready_text`가 `"없음"`이다.

#### `GET /network/drops`
"네트워크 · 정책에 막힌 흐름 (Hubble)".
- 파라미터: `from`, `to`, `namespace`(기본 `WATCH_NAMESPACES`의 첫 값), `limit`(기본 20)
```json
[{ "src_pod": "vuln-lab/log4shell-5dd4d9dd-z8c2x", "dst": "203.0.113.9 (world) · TCP 4444",
   "verdict": "DROPPED", "reason": "POLICY_DENIED", "direction": "EGRESS",
   "policy": "log4shell-egress-block", "count": 3, "time_ms": 1762146000000 }]
```
Hubble Relay `GetFlows`에서 `verdict=DROPPED`이고 출발지나 목적지 pod가 그 namespace(`source_pod`/`destination_pod` = `vuln-lab/`)인 흐름을 받는다. 같은 출발→목적지·포트·사유는 하나로 합쳐서 `count`에 더하고, `time_ms`는 마지막 시각으로 한다. 최근 순.

구현 (`app/hubble/`):
- `grpcio`로 Relay(`HUBBLE_RELAY_ADDR`)에 평문 채널로 붙는다. 이 클러스터 Relay는 `disable-server-tls: true`다. TLS를 켜면 클라이언트도 바꿔야 한다.
- `app/hubble/pb/`는 Cilium v1.20.2 `api/v1`의 `flow`, `relay`, `observer` proto를 grpcio-tools 1.85.1로 생성한 코드다(import 경로만 `app.hubble.pb.*`로 바꿈). Cilium을 올릴 때 다시 생성한다.
- 한 번에 최대 2000개 흐름을 받는다. **각 노드 Hubble 링 버퍼(노드당 약 4천 개)에 남은 흐름만 보이므로** 클러스터 전체 트래픽이 많으면 몇 분 전 흐름도 빠진다. 장기 보관이 필요하면 수집기로 따로 쌓아야 한다.
- 목적지가 pod가 아니면 DNS 이름(`destination_names`) → `IP (world)` 같은 예약 identity → IP 순으로 적는다.
- Relay 오류는 `502 hubble_error`(직전 값이 있으면 그 값), `HUBBLE_ENABLED=false`면 `503 hubble_unavailable`.

---

### 5.6 운영

| 엔드포인트 | 내용 |
|---|---|
| `GET /healthz` | 프로세스 생존 확인 (liveness) |
| `GET /readyz` | Tempo, Loki, 캐시 DB 연결 확인 (readiness) |
| `GET /metrics` | Prometheus 메트릭: 요청 수/지연, 외부 API 호출 수/실패, 캐시 적중률, AI 생성 시간, 사건 생성 수(상태별), Loki tail 지연, 재연결 횟수, Beyla 연결 성공률 |

---

## 6. 패널 ↔ 데이터 소스 매핑

| 대시보드 | 패널 | 소스 |
|---|---|---|
| ① | 조치 필요·미차단 / 차단 / 공격받은 워크로드 | `/incidents/summary` |
| ① | 경고 단계별 탐지 · 로그 기준 (Sigma level) | `/policies/levels` |
| ① | 수집 상태 | Prometheus (`up`, `kube_daemonset_status_number_ready`) |
| ① | 사건 큐 (단계·상태 열 포함) | `/incidents` |
| ① | 워크로드별 사건 | `/incidents/by-workload` |
| ① | 시간대별 사건 | `/incidents/timeseries` |
| ① | 정책 상태 | `/policies/stats` |
| ② | 상단 요약 | `/incidents/{trace_id}` |
| ② | Trace View | Tempo (백엔드가 기록한 사건 trace, `queryType: traceId`) |
| ② | AI 해석 | `/ai/analysis/{trace_id}` |
| ② | 원본 로그 | Loki (`{namespace="kube-system", container="export-stdout"} \|= "<exec_id>"`, parent_exec_id도 같은 방식) |
| ② | 출발지 IP 요약 | `/ti/ip/{ip}` |
| ③ | Geomap, IP 평판 표 | `/ti/ips` |
| ③ | 조회 수 / 고위험 / 사용량 / 캐시 | `/ti/summary` |
| ③ | 선택 IP 상세 | `/ti/ip/{ip}` |
| ③ | 파일 해시 | `/ti/files` |
| ④ | 노드 수, 보호 대상 워크로드 수, 노드 CPU/메모리 | Prometheus |
| ④ | 적용된 정책 / 격리된 워크로드 | `/infra/policies` |
| ④ | 노드 표 (역할, 커널, BPF LSM, Pod 수) | `/infra/nodes` |
| ④ | 워크로드 보호 현황 | `/infra/workloads` |
| ④ | 보안·관측 컴포넌트 | `/infra/components` |
| ④ | Hubble 차단 흐름 | `/network/drops` |

---

## 7. 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `TEFAL_API_TOKEN` | (필수) | Grafana → 백엔드 인증 토큰 |
| `TEMPO_URL` | `http://tempo.monitoring.svc.cluster.local:3200` | 조회 (Beyla span 검색) |
| `TEMPO_OTLP_URL` | `http://tempo.monitoring.svc.cluster.local:4318/v1/traces` | 사건 trace 기록 |
| `LOKI_URL` | `http://loki.monitoring.svc.cluster.local:3100` | Tetragon 로그 조회. loki-gateway에는 `/ready`가 없어 본체(single-binary)를 쓴다 |
| `PROMETHEUS_URL` | `http://kube-prometheus-stack-prometheus.monitoring:9090` | `total_workloads`(Running pod 수, kube-state-metrics) |
| `TEMPO_EXPORT_ENABLED` | `true` | 사건 trace 기록과 Beyla 연결 |
| `COLLECTOR_ENABLED` | `true` | Tetragon 수집기 |
| `COLLECT_INTERVAL_SEC` | `5` | 수집 주기. 병합 대기(`CORRELATE_MERGE_SEC`+5초)보다 오래된 구간만 처리한다 |
| `COLLECT_BACKFILL_HOURS` | `24` (배포 `168`) | 커서가 없을 때(첫 기동·DB 재생성) 거슬러 읽을 범위 |
| `COLLECT_CHUNK_SEC` | `3600` | 한 번에 읽는 Loki 구간 |
| `LOKI_TETRAGON_SELECTOR` | `{namespace="kube-system", container="export-stdout"}` | |
| `FALCO_WEBHOOK_TOKEN` | (선택) | Falcosidekick → 백엔드 인증. 없으면 `/ingest/falco`가 `503` |
| `FALCO_MIN_PRIORITY` | `Warning` | 이보다 낮은 경보는 기준점으로 쓰지 않음 |
| `CORRELATE_LOOKBACK_SEC` | `60` | 기준점 이전 역조회 범위 |
| `CORRELATE_MERGE_SEC` | `10` | 연속 차단 병합, 사건 확정 대기 |
| `FALCO_WAIT_SEC` | `30` | Falco 경보 뒤 차단을 기다리는 시간 |
| `CORRELATE_MAX_DEPTH` | `8` | ancestors 없이 parent를 따라 올라갈 최대 단계 |
| `HUBBLE_RELAY_ADDR` | `hubble-relay.kube-system.svc:80` | Relay gRPC (평문) |
| `HUBBLE_ENABLED` | `true` | ④ 차단 흐름 |
| `HUBBLE_TIMEOUT_SEC` | `10` | GetFlows 제한 시간 |
| `LOKI_FALCO_SELECTOR` | `{namespace="falco", container="falco"}` | ① 정책 상태의 Falco 룰 히트 |
| `K8S_ENABLED` | `true` | ④ 인프라 API. ServiceAccount 토큰이 없으면 자동으로 꺼진다 |
| `K8S_API_URL` | `https://kubernetes.default.svc` | |
| `FALCO_RULES_CONFIGMAP` | `falco/falco-rules` | Falco 커스텀 룰 ConfigMap (`namespace/name`) |
| `ABUSEIPDB_API_KEY` | (필수) | |
| `ABUSEIPDB_DAILY_LIMIT` | `1000` | |
| `VIRUSTOTAL_API_KEY` | (필수) | |
| `VIRUSTOTAL_DAILY_LIMIT` | `500` | |
| `VIRUSTOTAL_PER_MIN` | `4` | |
| `GEOIP_CITY_DB` | `/data/GeoLite2-City.mmdb` | |
| `GEOIP_ASN_DB` | `/data/GeoLite2-ASN.mmdb` | |
| `GEMINI_API_KEY` | (필수) | |
| `GEMINI_MODEL` | (설정) | 사용할 Gemini 모델 ID |
| `TI_CACHE_TTL_HOURS` | `24` | |
| `AI_CACHE_TTL_DAYS` | `7` | |
| `AI_REFRESH_PER_MIN` | `5` | |
| `FP_THRESHOLD` | `5` | 오탐 의심 기준 히트 수 |
| `CACHE_DB` | `sqlite:////data/tefal.db` | 또는 `redis://...` |
| `WATCH_NAMESPACES` | `vuln-lab` | |
| `SIGMA_LEVELS_FILE` | `/config/sigma_levels.yaml` | 경고 단계 매칭 표 (4.8) |

API 키는 K8s `Secret`으로 주입한다. 이미지와 ConfigMap에 넣지 않는다.

---

## 8. 보안 요구사항

- **RBAC:** ServiceAccount `monitoring/tefal-backend`.
  - ClusterRole `tefal-backend-read`: `pods`, `nodes`, `daemonsets`·`deployments`·`statefulsets`, `tracingpolicies`, `tracingpoliciesnamespaced`, `ciliumnetworkpolicies`, `ciliumclusterwidenetworkpolicies`에 `get/list`만 준다.
  - Role `falco/tefal-backend-falco-rules`: ConfigMap `falco-rules` 하나에 `get`만 준다(`resourceNames`).
  - Secret, ConfigMap 목록, `create/update/delete/exec`는 주지 않는다. 실제 클러스터에서 `kubectl auth can-i`로 확인했다.
- **네트워크:** `CiliumNetworkPolicy`로 ingress는 Grafana, Prometheus(지표 수집), Falcosidekick core(`falco` namespace)만 허용한다. egress는 Tempo(3200, 4318), Loki(3100), Prometheus(9090), K8s API, Hubble Relay(4245), DNS(nodelocaldns), `pypi.org`·`files.pythonhosted.org`(빌드 없는 배포의 의존성 설치)만 허용한다. `api.abuseipdb.com`, `www.virustotal.com`, `generativelanguage.googleapis.com`은 해당 기능 단계에서 추가한다. 현재 정책은 `deploy/backend/gen_backend.py`가 만든다.
- **로그 속 비밀값:** Tetragon 이벤트의 `arguments`에는 명령 인자가 그대로 들어 있어서 비밀번호가 섞일 수 있다(실제 클러스터에서 `curl -u admin:<비밀번호>`가 확인됨). AI 프롬프트, 사건 요약, Tempo span 속성에 넣기 전에 `-u user:pass`, `--password=`, `Authorization:`, `token=` 같은 패턴을 `<가림>`으로 바꾼다.
- **입력 검증:** `trace_id`는 hex 32자, `ip`는 `ipaddress` 모듈로 검증한다. TraceQL/LogQL에 사용자 입력을 문자열로 이어 붙이지 않는다.
- **로그:** API 키와 Authorization 헤더는 로그에 남기지 않는다.
- **컨테이너:** non-root, `readOnlyRootFilesystem`(캐시 경로 `/data`만 쓰기 가능).

---

## 9. 미결정 사항

1. **파일 SHA-256 출처:** Tetragon 기본 이벤트에는 파일 해시가 없다.
   - A안: Tetragon `security_file_open`/`file_write` 정책에 IMA hash(`imaHash`) 수집 옵션을 켠다 (커널 IMA 지원 필요). **권장**
   - B안: 백엔드가 pod에서 파일을 직접 읽는다. `pods/exec` 권한이 필요해 조회 전용 원칙과 충돌한다. **비권장**
2. **BPF LSM 활성 여부:** 노드 라벨로 관리할지, Tetragon 시작 로그(`BPF LSM enabled`)를 Loki에서 읽을지 정해야 한다.
3. **캐시 저장소:** 단일 replica면 SQLite + PVC, 여러 replica면 Redis를 쓴다.
4. **Tetragon `ancestors` 활성화 (사람이 결정·적용):** Tetragon Helm values에서 `process_lsm`, `process_kprobe`, `process_uprobe` 이벤트에 ancestors를 켜야 4.3의 계보 확보가 한 번에 된다. 이벤트 크기가 커지므로 Loki 사용량을 먼저 확인한다. 켜지 않으면 parent 단계별 재조회로 동작하지만 느리다.
5. ~~**Falcosidekick webhook 설정**~~ → 적용함(2026-11-04, Falco helm revision 4). `deploy/falco/webhook-values.example.yaml`, 절차는 `deploy/README.md`.
6. **Beyla 계측 범위:** php2shell·react2shell은 HTTP trace가 들어온다(최종 정책 공격 14건 모두 연결). **log4shell(Java)은 7일간 trace가 1건뿐**이라 연결되지 않는다. Beyla 설정 확인이 필요하다.
   - 출발지 IP: NodePort가 master에서 SNAT되어 `client.address`가 master 내부 IP(`10.233.66.37`)로 보인다. 접속 방식은 바꾸지 않기로 했다.
7. **묶기 기준값:** `CORRELATE_LOOKBACK_SEC=60`, `CORRELATE_MERGE_SEC=10`, `FALCO_WAIT_SEC=30`은 시작값이다. 실제 공격 시나리오를 돌려 보고 조정한다.
8. ~~**Sigma 매칭 표**~~ → 받아서 적용함(`tefal-backend/config/sigma_levels.yaml`). Falco 룰은 표에 없어 priority 기본값을 쓴다.
