# react2shell (운영 배포본 — 3개)

팀원 최종본을 우리 규칙(`<취약점>-<계층>-<훅지점>-<동작>`) + `tefal.io/` 라벨로 정리.
**운영에 실제 쓰는 3개만** 이 폴더에 둠. (미배포·연구용 포함 7개 전부는 원본 `..\..\tetragon-policies\react2shell\` 에 보존)

## 운영 3개
| 파일 | 역할 | action |
|---|---|---|
| `react2shell-uprobe-uvspawn-observe.yaml` | Node 프로세스 생성 관측 | Post (tetra-sync.sh로 적용) |
| `react2shell-kprobe-processflow-observe.yaml` | clone/clone3/execve 관찰 | Post |
| `react2shell-lsm-bprmcheck-shell-block.yaml` | ★ 셸 실행 차단 | **Sigkill** |

## 배포
- 네임스페이스 정책: `kubectl apply -k .` (processflow + shell-block)
- uprobe(uvspawn): 상위 `..\tetra-sync.sh` (현재 PID 자동 주입)

## 미배포 (원본 폴더에만 보존)
shell-detect(lsm 관찰) · stage1 전체관찰 · syncspawn · v8property(연구용)

## 한계 (팀원 README 요약)
- uv_spawn 옵션 포인터 → 실제 명령 문자열 직접 추출 미완.
- 모든 RCE 차단 일반화 불가. Cilium/Hubble 미구현.
