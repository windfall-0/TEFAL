# tetragon-policies-final (운영 배포본 — 필수만)

`tetragon-policies/` 에서 **운영에 꼭 필요한 정책만** 추린 깨끗한 배포 세트.
제외: 옛 네이밍(`이전버전/`), `archive/`, 옛 `sync-uprobe.sh`. (react2shell 연구·실험용 syncspawn·v8·processflow는 **표시만 하고 포함**)

## 구성 (3 취약점 · 우리 네이밍)
| 폴더 | 정책 | 비고 |
|---|---|---|
| `log4shell/` | 8개 (egress·LSM차단★·kprobe 5·uprobe) + kustomization | Java |
| `php2shell/` | 4개 (LSM차단★·kprobe·uprobe 2) + kustomization + php-sync.sh | Apache/PHP |
| `react2shell/` | 7개 (운영 3: uvspawn·processflow·shell-block, 미배포 4) + kustomization + README | Node.js |
| `tetra-sync.sh` | 통합 PID 동기화 + 전체 배포 | 공통 |

> ★ = 핵심 차단(LSM Override). 3개 취약점 모두 LSM Override로 차단(동일 구조).

## 배포 순서
```bash
# tetra-sync.sh 한 방에: uprobe PID 동기화 + 각 폴더 kustomization 적용
./tetra-sync.sh            # (--dry: PID만 교체, 적용 안 함)
```

## 주의
- **클러스터 적용은 팀 합의 + 유지보수 시간에.** 옛 이름 정책 삭제 → 새 이름 적용 → `tetra tracingpolicy list` 확인 + 무해 테스트.
- **react2shell LSM 3단계(observe/shell-observe/shell-block)는 동시 적용 금지** — 기본 운영은 `shell-block`.
- tetra-sync.sh 의 log4shell·react2shell 부분은 아직 클러스터 미검증(php2shell 방식 일반화본).
