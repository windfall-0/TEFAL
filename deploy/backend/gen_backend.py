"""tefal-backend 배포 매니페스트 생성 (빌드 없이 실행: python:3.12-slim + initContainer uv sync + 코드 ConfigMap).

python gen_backend.py <tefal-backend 디렉터리> <출력 디렉터리>
"""
import glob, json, os, sys

SRC, OUT = sys.argv[1], sys.argv[2]
NS = "monitoring"
IMAGE = "docker.io/library/python:3.12.8-slim"
LABELS = {"app.kubernetes.io/name": "tefal-backend", "app.kubernetes.io/part-of": "tefal"}

files = sorted(glob.glob(os.path.join(SRC, "app", "**", "*.py"), recursive=True))
files += [os.path.join(SRC, f) for f in ("allowlist.yaml", "pyproject.toml", "uv.lock")]
data, items = {}, []
for f in files:
    rel = os.path.relpath(f, SRC).replace("\\", "/")
    key = rel.replace("/", "__")
    data[key] = open(f, encoding="utf-8").read()
    items.append({"key": key, "path": rel})

code_cm = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": "tefal-backend-code", "namespace": NS, "labels": LABELS}, "data": data}

# 경고 단계 매칭 표 (4.8). 파일만 바꿔 다시 적용하면 백엔드가 재시작 없이 다시 읽는다.
sigma_cm = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "tefal-sigma-levels", "namespace": NS, "labels": LABELS},
            "data": {"sigma_levels.yaml": open(os.path.join(SRC, "config", "sigma_levels.yaml"), encoding="utf-8").read()}}

INIT = r"""set -eu
python -m pip install --no-cache-dir -q --target /tmp/uvpkg uv==0.5.11
mkdir -p /tmp/proj && cp /src/pyproject.toml /src/uv.lock /tmp/proj/
cd /tmp/proj
/tmp/uvpkg/bin/uv sync --frozen --no-dev --no-install-project
/deps/venv/bin/python -c "import fastapi, uvicorn, aiosqlite; print('deps ok')"
"""

sec = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
       "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
       "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}

deploy = {
    "apiVersion": "apps/v1", "kind": "Deployment",
    "metadata": {"name": "tefal-backend", "namespace": NS, "labels": LABELS},
    "spec": {
        "replicas": 1, "strategy": {"type": "Recreate"},  # SQLite + RWO PVC
        "selector": {"matchLabels": {"app.kubernetes.io/name": "tefal-backend"}},
        "template": {
            "metadata": {"labels": LABELS},
            "spec": {
                # ④ 인프라: K8s API 읽기 전용 (아래 RBAC). 토큰은 이 SA 것만 마운트된다
                "serviceAccountName": "tefal-backend",
                "automountServiceAccountToken": True,
                "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [{"matchExpressions": [
                        {"key": "kubernetes.io/hostname", "operator": "In", "values": ["k8s-worker2"]}]}]}}},
                "securityContext": {"fsGroup": 10001},
                "initContainers": [{
                    "name": "deps", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["sh", "-c", INIT],
                    "env": [{"name": "HOME", "value": "/tmp"},
                            {"name": "UV_PROJECT_ENVIRONMENT", "value": "/deps/venv"},
                            {"name": "UV_CACHE_DIR", "value": "/tmp/uvcache"},
                            {"name": "UV_PYTHON_DOWNLOADS", "value": "never"},
                            {"name": "UV_COMPILE_BYTECODE", "value": "1"},
                            {"name": "UV_LINK_MODE", "value": "copy"}],
                    "securityContext": sec,
                    "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}},
                    "volumeMounts": [{"name": "deps", "mountPath": "/deps"}, {"name": "tmp", "mountPath": "/tmp"},
                                     {"name": "code", "mountPath": "/src"}],
                }],
                "containers": [{
                    # 컨테이너 이름 = Loki container 라벨 → 사건 요약 줄 {namespace="monitoring", container="tefal-backend"}
                    "name": "tefal-backend", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                    "workingDir": "/app",
                    "command": ["/deps/venv/bin/uvicorn", "app.main:create_app", "--factory",
                                "--host", "0.0.0.0", "--port", "8000", "--no-access-log"],
                    "ports": [{"name": "http", "containerPort": 8000}],
                    "envFrom": [{"secretRef": {"name": "tefal-backend-token"}}],
                    "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                            {"name": "PYTHONUNBUFFERED", "value": "1"},
                            {"name": "TEMPO_URL", "value": "http://tempo.monitoring.svc.cluster.local:3200"},
                            {"name": "TEMPO_OTLP_URL", "value": "http://tempo.monitoring.svc.cluster.local:4318/v1/traces"},
                            # loki-gateway에는 /ready 경로가 없어 본체를 직접 쓴다
                            {"name": "LOKI_URL", "value": "http://loki.monitoring.svc.cluster.local:3100"},
                            {"name": "WATCH_NAMESPACES", "value": "vuln-lab"},
                            {"name": "PROMETHEUS_URL", "value": "http://kube-prometheus-stack-prometheus.monitoring:9090"},
                            # 첫 기동 시 지난 7일 Tetragon 로그로 사건을 만든다 (이후엔 커서부터 이어 읽음)
                            {"name": "COLLECT_BACKFILL_HOURS", "value": "168"},
                            # 시연 모드: 사건 응답의 내부 출발지 IP를 아래 공인 IP 중 하나로 바꿔 보여 준다(사건마다 고름).
                            # DB·Loki·Tempo는 원본. 화면에는 '시연용'이 붙는다. 끄려면 빈 문자열.
                            # 공개적으로 인터넷 스캔을 하는 연구·스캐너 기관 IP만 쓴다(역방향 DNS로 확인, 2026-11-04):
                            #   Censys(US) · Shodan(US·IS·NL) · Driftnet/internet-measurement(GB) · Shadowserver(US)
                            #   · internet-census.org(PT) · ONYPHE(FR 기관, US 위치) · 중국 3개(아래 설명)
                            {"name": "DEMO_SRC_IP_POOL",
                             "value": ",".join([
                                 "162.142.125.10", "167.94.138.35",                 # Censys
                                 "71.6.199.23", "66.240.205.34",                    # Shodan (US)
                                 "82.221.105.6",                                    # Shodan (IS)
                                 "89.248.167.131", "80.82.77.139",                  # Shodan (NL)
                                 "87.236.176.100", "193.163.125.10",                # Driftnet (GB)
                                 "64.62.197.10",                                    # Shadowserver
                                 "45.156.128.10",                                   # internet-census.org
                                 "91.230.168.10",                                   # ONYPHE
                                 # 중국: 스캐너 기관으로 확인되는 IP가 없어, AbuseIPDB 블랙리스트(신뢰도 100,
                                 # 2026-11-04 신고)의 클라우드·IDC 대역에서 골랐다. 실제 공격 신고가 쌓인 IP다
                                 "118.145.148.31",                                  # Volcano Engine (CN)
                                 "114.67.232.93",                                   # China Unicom Beijing (CN)
                                 "219.144.80.143"])},                               # Chinanet Shaanxi Cloud Base (CN)
                            # 5단계 AI 해석 (키는 Secret tefal-backend-token의 GEMINI_API_KEY)
                            {"name": "GEMINI_MODEL", "value": "gemini-flash-latest"},
                            {"name": "CACHE_DB", "value": "sqlite:////data/tefal.db"}],
                    "securityContext": sec,
                    "resources": {"requests": {"cpu": "50m", "memory": "256Mi"}, "limits": {"memory": "512Mi"}},
                    "readinessProbe": {"httpGet": {"path": "/readyz", "port": "http"}, "periodSeconds": 15, "timeoutSeconds": 8},
                    "livenessProbe": {"httpGet": {"path": "/healthz", "port": "http"}, "periodSeconds": 20,
                                      "timeoutSeconds": 5, "failureThreshold": 3},
                    "volumeMounts": [{"name": "deps", "mountPath": "/deps", "readOnly": True},
                                     {"name": "tmp", "mountPath": "/tmp"},
                                     {"name": "data", "mountPath": "/data"},
                                     {"name": "code", "mountPath": "/app", "readOnly": True},
                                     # subPath 없이 디렉터리로 마운트해야 ConfigMap 수정이 반영된다
                                     {"name": "sigma", "mountPath": "/config", "readOnly": True}],
                }],
                "volumes": [{"name": "deps", "emptyDir": {"sizeLimit": "512Mi"}},
                            {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}},
                            {"name": "data", "persistentVolumeClaim": {"claimName": "tefal-backend-data"}},
                            {"name": "code", "configMap": {"name": "tefal-backend-code", "items": items}},
                            {"name": "sigma", "configMap": {"name": "tefal-sigma-levels"}}],
            },
        },
    },
}

# ---- RBAC (BACKEND_API.md 8장): get/list만. create/update/delete/exec 없음
sa = {"apiVersion": "v1", "kind": "ServiceAccount",
      "metadata": {"name": "tefal-backend", "namespace": NS, "labels": LABELS}}
cluster_role = {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
    "metadata": {"name": "tefal-backend-read", "labels": LABELS},
    "rules": [
        {"apiGroups": [""], "resources": ["pods", "nodes"], "verbs": ["get", "list"]},
        {"apiGroups": ["apps"], "resources": ["daemonsets", "deployments", "statefulsets"], "verbs": ["get", "list"]},
        {"apiGroups": ["cilium.io"], "verbs": ["get", "list"],
         "resources": ["tracingpolicies", "tracingpoliciesnamespaced",
                       "ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"]},
    ],
}
cluster_binding = {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
    "metadata": {"name": "tefal-backend-read", "labels": LABELS},
    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "tefal-backend-read"},
    "subjects": [{"kind": "ServiceAccount", "name": "tefal-backend", "namespace": NS}],
}
# Falco 커스텀 룰 ConfigMap 하나만 (configmaps 전체 읽기 권한은 주지 않는다)
falco_role = {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
    "metadata": {"name": "tefal-backend-falco-rules", "namespace": "falco", "labels": LABELS},
    "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["falco-rules"], "verbs": ["get"]}],
}
falco_binding = {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
    "metadata": {"name": "tefal-backend-falco-rules", "namespace": "falco", "labels": LABELS},
    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "tefal-backend-falco-rules"},
    "subjects": [{"kind": "ServiceAccount", "name": "tefal-backend", "namespace": NS}],
}

pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
       "metadata": {"name": "tefal-backend-data", "namespace": NS, "labels": LABELS},
       "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "local-path",
                "resources": {"requests": {"storage": "1Gi"}}}}

svc = {"apiVersion": "v1", "kind": "Service",
       "metadata": {"name": "tefal-backend", "namespace": NS, "labels": LABELS},
       "spec": {"type": "ClusterIP", "selector": {"app.kubernetes.io/name": "tefal-backend"},
                "ports": [{"name": "http", "port": 8000, "targetPort": "http"}]}}

sm = {"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor",
      "metadata": {"name": "tefal-backend", "namespace": NS, "labels": {**LABELS, "release": "kube-prometheus-stack"}},
      "spec": {"selector": {"matchLabels": {"app.kubernetes.io/name": "tefal-backend"}},
               "endpoints": [{"port": "http", "path": "/metrics", "interval": "30s"}]}}

DNS_PORTS = {"ports": [{"port": "53", "protocol": "UDP"}, {"port": "53", "protocol": "TCP"}],
             "rules": {"dns": [{"matchPattern": "*"}]}}


def ep(ns, labels):
    return {"matchLabels": {"k8s:io.kubernetes.pod.namespace": ns, **labels}}

cnp = {
    "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
    "metadata": {"name": "tefal-backend", "namespace": NS, "labels": LABELS},
    "spec": {
        "endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "tefal-backend"}},
        "ingress": [{
            "fromEndpoints": [ep(NS, {"app.kubernetes.io/name": "grafana"}),
                              ep(NS, {"app.kubernetes.io/name": "prometheus"}),
                              # Falcosidekick webhook (POST /ingest/falco)
                              ep("falco", {"app.kubernetes.io/name": "falcosidekick", "app.kubernetes.io/component": "core"})],
            "toPorts": [{"ports": [{"port": "8000", "protocol": "TCP"}]}],
        }],
        "egress": [
            # DNS: nodelocaldns(169.254.25.10, hostNetwork) → FQDN 정책용 DNS 가시성
            # (Cilium: toCIDR와 toEntities는 한 규칙에 같이 못 쓴다)
            {"toCIDR": ["169.254.25.10/32"], "toPorts": [DNS_PORTS]},
            {"toEntities": ["host"], "toPorts": [DNS_PORTS]},
            {"toEndpoints": [ep(NS, {"app.kubernetes.io/name": "loki", "app.kubernetes.io/component": "single-binary"})],
             "toPorts": [{"ports": [{"port": "3100", "protocol": "TCP"}]}]},
            {"toEndpoints": [ep(NS, {"app.kubernetes.io/name": "tempo"})],
             "toPorts": [{"ports": [{"port": "3200", "protocol": "TCP"}, {"port": "4318", "protocol": "TCP"}]}]},
            # Running pod 수 (kube-state-metrics)
            {"toEndpoints": [ep(NS, {"app.kubernetes.io/name": "prometheus"})],
             "toPorts": [{"ports": [{"port": "9090", "protocol": "TCP"}]}]},
            {"toEntities": ["kube-apiserver"], "toPorts": [{"ports": [{"port": "6443", "protocol": "TCP"}]}]},
            # ④ Hubble 차단 흐름: Relay gRPC (Service 80 → 컨테이너 4245, 서버 TLS 꺼짐)
            {"toEndpoints": [ep("kube-system", {"k8s-app": "hubble-relay"})],
             "toPorts": [{"ports": [{"port": "4245", "protocol": "TCP"}]}]},
            # 5단계 위협 인텔리전스·AI 해석 (공인 IP 평판, Gemini)
            {"toFQDNs": [{"matchName": "api.abuseipdb.com"}, {"matchName": "www.virustotal.com"},
                         {"matchName": "generativelanguage.googleapis.com"}],
             "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}]}]},
            # initContainer 의존성 설치 (uv sync)
            {"toFQDNs": [{"matchName": "pypi.org"}, {"matchName": "files.pythonhosted.org"}],
             "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}]}]},
        ],
    },
}

os.makedirs(OUT, exist_ok=True)
json.dump(code_cm, open(os.path.join(OUT, "10-code-configmap.json"), "w", encoding="utf-8"), ensure_ascii=False)
json.dump(sigma_cm, open(os.path.join(OUT, "15-sigma-configmap.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
with open(os.path.join(OUT, "20-backend.json"), "w", encoding="utf-8") as f:
    json.dump({"apiVersion": "v1", "kind": "List", "items": [sa, cluster_role, cluster_binding, falco_role, falco_binding,
                                                  pvc, deploy, svc, sm, cnp]}, f, ensure_ascii=False, indent=1)
print("files:", len(items), "cm bytes:", sum(len(v.encode()) for v in data.values()))
