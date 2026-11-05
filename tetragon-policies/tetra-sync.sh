#!/bin/bash
# Unified Tetragon uprobe PID sync + apply for 3 vulns (php2shell / log4shell / react2shell)
# Run from master node. Place at tetragon-policies(-final)/ root (next to the team folders).
# usage:  ./tetra-sync.sh         sync uprobe PIDs + apply every team folder present
#         ./tetra-sync.sh --dry   sync PIDs only, no apply(no delete)
#
# [수정 2026-11-04]
#   ① log4shell uprobe 파일명 정정: log4shell-uprobe-forkandexec-observe.yaml
#   ② uprobe를 'apply -f'로 직접 재적용 — 기존엔 delete만 하고 apply -k(kustomization)에 uprobe가
#      없으면 다시 안 올라오던 버그 수정. (--dry 일 때는 delete/apply 안 함)
set -euo pipefail
cd "$(dirname "$0")"

NS=vuln-lab
TEAMS="php2shell log4shell react2shell"

# relative file | pod label | anchor binary (container path after /root)
UPROBE_MAP="
php2shell/php2shell-uprobe-zifsystem-observe.yaml|app=php2shell|/usr/lib/apache2/modules/libphp.so
php2shell/php2shell-uprobe-popen-observe.yaml|app=php2shell|/usr/lib/apache2/modules/libphp.so
log4shell/log4shell-uprobe-forkandexec-observe.yaml|app=log4shell|/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64/libjava.so
react2shell/react2shell-uprobe-uvspawn-observe.yaml|app=react2shell|/usr/local/bin/node
"

find_pid() {
  local label="$1" anchor="$2" pod node uid uid_us tg
  pod=$(kubectl get pod -n "$NS" -l "$label" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -z "$pod" ] && return 0
  node=$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.spec.nodeName}')
  uid=$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.metadata.uid}')
  uid_us=${uid//-/_}
  tg=$(kubectl get pod -n kube-system -l app.kubernetes.io/name=tetragon --field-selector spec.nodeName="$node" -o jsonpath='{.items[0].metadata.name}')
  [ -z "$tg" ] && return 0
  kubectl exec -n kube-system "$tg" -c tetragon -- sh -c "for p in /procRoot/[0-9]*; do [ -e \$p/root$anchor ] && grep -qE '$uid|$uid_us' \$p/cgroup 2>/dev/null && echo \${p##*/}; done; true" | sort -n | head -1
}

DRY="${1:-}"

echo "== uprobe PID sync =="
while IFS='|' read -r file label anchor; do
  [ -z "${file// }" ] && continue
  [ -f "$file" ] || { echo "[skip] no file: $file"; continue; }
  pid=$(find_pid "$label" "$anchor")
  [ -z "$pid" ] && { echo "[FAIL] PID not found: $file ($label $anchor)"; exit 1; }
  sed -i -E "s#/procRoot/[^/]+/root#/procRoot/$pid/root#g" "$file"
  echo "[$file] -> PID $pid"
  if [ "$DRY" != "--dry" ]; then
    kubectl delete -f "$file" --ignore-not-found >/dev/null 2>&1 || true
    kubectl apply -f "$file"          # [FIX] uprobe 직접 재적용 (kustomization에 없어도 적용)
  fi
done <<EOF
$UPROBE_MAP
EOF

if [ "$DRY" = "--dry" ]; then
  echo "dry: not applied"
  exit 0
fi

echo "== apply (per team folder present) =="
for d in $TEAMS; do
  if [ -f "$d/kustomization.yaml" ]; then
    echo "apply -k $d"
    kubectl apply -k "$d"
  else
    echo "[skip] no folder/kustomization: $d"
  fi
done

echo "== status (per node) =="
for tg in $(kubectl get pod -n kube-system -l app.kubernetes.io/name=tetragon -o jsonpath='{.items[*].metadata.name}'); do
  echo "--- $tg ---"
  kubectl exec -n kube-system "$tg" -c tetragon -- tetra tracingpolicy list 2>/dev/null | grep -E 'php2shell|log4shell|react2shell|r2s' || true
done
