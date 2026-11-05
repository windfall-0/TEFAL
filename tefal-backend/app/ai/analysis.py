"""AI 해석 · 대응 가이드 (5.3).

- 입력: 사건 정보 + 사건에 묶인 Tetragon 이벤트(1초 안 반복은 접어서 최대 50줄) + Falco 룰 + 출발지 TI 요약.
  명령 인자는 correlate.redact로 비밀값을 가린 뒤 넣는다.
- 근거(evidence)는 모델이 입력 줄 번호(E1, E2 …)로만 고르게 하고, 서버가 그 번호를 실제 입력 줄로 바꾼다.
  입력에 없는 번호는 버린다. 그래서 모델이 지어낸 로그 줄은 화면에 나오지 않는다.
- 결과는 AI_CACHE_TTL_DAYS 동안 캐시한다. 같은 사건의 동시 요청은 한 번만 만든다.
"""

import asyncio
import datetime
import logging
import os
import re
import time

from app.ai.gemini import GeminiClient, GeminiError
from app.ai.mask import Masker, hook_help, hook_name, runtime_text
from app.config import Settings
from app.core.cache import SqliteCache
from app.core.timefmt import fmt_hms
from app.incidents import correlate, dedup
from app.incidents.events import incident_events
from app.incidents.store import Incident, IncidentStore
from app.incidents.tetragon import TetragonEvent

log = logging.getLogger(__name__)

NS = 1_000_000_000
MAX_LINES = 50
RETRY_WAIT_SEC = 3.0
DISCLAIMER = "AI가 생성한 해석입니다. 근거 로그와 대조해 확인하세요."
VERDICTS = ["공격", "오탐 의심", "판단 불가"]
RISKS = ["높음", "중간", "낮음"]
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING", "description": "무슨 일이 있었는지 2~3문장"},
        "verdict": {"type": "STRING", "enum": VERDICTS},
        "risk": {"type": "STRING", "enum": RISKS},
        "mitre": {"type": "ARRAY", "items": {"type": "OBJECT", "properties": {
            "id": {"type": "STRING"}, "name": {"type": "STRING"}}, "required": ["id", "name"]}},
        "evidence": {"type": "ARRAY", "items": {"type": "OBJECT", "properties": {
            "line": {"type": "STRING", "description": "입력 이벤트 줄 번호 (예: E3)"},
            "why": {"type": "STRING", "description": "이 줄이 근거인 이유 한 문장"}}, "required": ["line", "why"]}},
        "guide": {"type": "ARRAY", "items": {"type": "STRING"}, "description": "대응 가이드 3~5개"},
    },
    "required": ["summary", "verdict", "risk", "mitre", "evidence", "guide"],
}

SYSTEM = (
    "너는 Kubernetes 런타임 보안 분석가다. 주어진 사건 정보와 eBPF(Tetragon)·Falco 이벤트만 근거로 판단한다. "
    "추측은 summary에 '추정'이라고 밝힌다. evidence에는 입력 이벤트의 줄 번호(E1 형식)만 쓴다. "
    "guide는 운영자가 바로 할 수 있는 구체적 조치로 쓴다. 모든 문장은 한국어로 쓴다."
)


# ---- 입력 만들기 ----

def _parts(e: TetragonEvent, run_count: int, tz: str, mask=None) -> str:
    """이벤트 한 줄. mask가 있으면 모델용: 정책 이름 대신 훅 설명, 이름은 가림."""
    p = e.process
    m = mask or (lambda x: x or "")
    parts = [fmt_hms(e.time_ns // 1_000_000, tz), e.event_type.removeprefix("process_")]
    if mask is None:
        if e.policy:
            parts.append(f"policy={e.policy}")
        if e.function:
            parts.append(f"fn={e.function}")
        if e.action:
            parts.append(f"action={e.action.removeprefix('KPROBE_ACTION_')}")
    elif e.policy:  # exec/exit 같은 기본 이벤트에는 훅이 없다
        parts.append(f"훅={hook_name(e)}")
    parts.append(f"binary={m(p.binary)}")
    if p.arguments:
        parts.append(f'args="{m(correlate.redact(p.arguments))[:200]}"')
    if e.file_arg:
        parts.append(f"target={m(correlate.redact(e.file_arg))[:120]}")
    if e.parent:
        parts.append(f"parent={m(os.path.basename(e.parent.binary))}")
    if run_count > 1:
        parts.append(f"×{run_count}")
    return " ".join(parts)


def event_rows(events: list[TetragonEvent], tz: str, gap_ns: int, masker=None) -> list[dict]:
    """[{display: 화면용 원래 줄, masked: 모델용 줄, event}]. 반복은 접고 ×N. 최대 MAX_LINES줄."""
    rows = []
    for run in dedup.collapse(events, dedup.tetragon_key, lambda e: e.time_ns, gap_ns):
        e = run.first
        rows.append({"display": _parts(e, run.count, tz),
                     "masked": _parts(e, run.count, tz, masker or (lambda x: x or "")),
                     "event": e})
    if len(rows) > MAX_LINES:
        # 차단(기준점) 줄은 남기고 앞쪽부터 자른다
        blocked = [r for r in rows if r["event"].is_anchor]
        rest = [r for r in rows if not r["event"].is_anchor][: max(0, MAX_LINES - len(blocked))]
        keep = {id(r) for r in rest + blocked[:MAX_LINES]}
        rows = [r for r in rows if id(r) in keep]
    return rows


def event_lines(events: list[TetragonEvent], tz: str, gap_ns: int) -> list[str]:
    """화면용 원래 줄만."""
    return [r["display"] for r in event_rows(events, tz, gap_ns)]


def build_prompt(inc: Incident, rows: list[dict], ti: dict | None, tz: str, masker: Masker, level_of=None) -> str:
    """모델 입력. 실습 환경 이름(namespace·pod·정책·이미지)은 가리고 훅 설명을 붙인다 (mask.py)."""
    anchor = next((r["event"] for r in rows if r["event"].is_anchor), None)
    head = [
        f"사건 시각: {fmt_hms(inc.start_ms, tz)} ~ {fmt_hms(inc.last_ms, tz)}",
        f"대상: 컨테이너로 실행 중인 {runtime_text(inc)}",
        f"상태: {'차단됨' if inc.status == 'blocked' else inc.status} · 조치 {inc.action}"
        + (f" · 기준 훅 {hook_name(anchor)}" if anchor else "") + f" · 경고 단계 {inc.level}",
        f"행위 요약: {masker(inc.summary)}",
        f"Falco 룰: {', '.join(masker(r) for r in inc.falco_rules) or '없음'}",
        f"출발지 IP: {inc.src_ip or '알 수 없음'}"
        + (" (사설/내부 IP. NodePort SNAT로 실제 출발지가 가려졌을 수 있음)" if ti is None else ""),
    ]
    if ti:
        head.append(f"출발지 TI: 국가 {ti.get('country') or '-'}, ASN {ti.get('asn_isp') or '-'}, "
                    f"AbuseIPDB {ti.get('abuse_score')}, VirusTotal 악성 {ti.get('vt_text') or '-'}")
    hooks = {}
    for r in rows:
        e = r["event"]
        if e.policy and hook_name(e) not in hooks:
            level = level_of(e.policy) if level_of else None
            hooks[hook_name(e)] = " · ".join(x for x in (hook_help(e), f"경고 단계 {level}" if level else None) if x)
    hook_lines = [f"- {k}: {v or '설명 없음'}" for k, v in hooks.items()] or ["(정책이 걸린 이벤트 없음)"]
    body = [f"E{i + 1}: {r['masked']}" for i, r in enumerate(rows)] or ["(이벤트 없음)"]
    prompt = "\n".join(["[사건]", *head, "", "[걸린 훅] (탐지·차단 정책이 감시하는 지점)", *hook_lines, "",
                         "[이벤트] (시간순, ×N = 1초 안 반복 횟수)", *body])
    leaked = masker.leaks(prompt)
    if leaked:  # 남은 이름이 있으면 한 번 더 가린다
        log.warning("AI 입력에 가릴 이름이 남아 다시 가림: %s", leaked)
        prompt = masker(prompt)
    return prompt


# ---- 결과 다듬기 ----

def finalize(raw: dict, lines: list[str]) -> dict:
    """모델 출력 검증: enum 밖 값은 '판단 불가'/'중간', 근거는 입력 줄만, MITRE ID 형식 확인."""
    by_id = {f"E{i + 1}": x for i, x in enumerate(lines)}
    evidence = []
    for ev in raw.get("evidence") or []:
        lid = str((ev or {}).get("line", "")).strip().upper()
        if lid in by_id and by_id[lid] not in [e["line"] for e in evidence]:
            evidence.append({"line": by_id[lid], "why": str(ev.get("why", ""))[:200]})
    mitre = [{"id": m["id"].strip(), "name": str(m.get("name", ""))[:60]}
             for m in raw.get("mitre") or [] if isinstance(m, dict) and _MITRE_RE.match(str(m.get("id", "")).strip())]
    return {
        "summary": str(raw.get("summary", ""))[:1000],
        "verdict": raw.get("verdict") if raw.get("verdict") in VERDICTS else "판단 불가",
        "risk": raw.get("risk") if raw.get("risk") in RISKS else "중간",
        "mitre": mitre[:6],
        "evidence": evidence[:8],
        "guide": [str(g)[:300] for g in raw.get("guide") or []][:6],
    }


def render_markdown(d: dict) -> str:
    md = [f"**판정: {d['verdict']} · 위험도 {d['risk']}**", "", d["summary"], ""]
    if d["mitre"]:
        md += ["**MITRE ATT&CK**", *[f"- `{m['id']}` {m['name']}" for m in d["mitre"]], ""]
    if d["evidence"]:
        md += ["**근거 로그**", *[f"- `{e['line'][:160]}`  \n  {e['why']}" for e in d["evidence"]], ""]
    if d["guide"]:
        md += ["**대응 가이드**", *[f"{i + 1}. {g}" for i, g in enumerate(d["guide"])], ""]
    md += [f"<small>{d['model']} · {d['cached_at']} 생성 · {DISCLAIMER}</small>"]
    return "\n".join(md)


# ---- 서비스 ----

class AiUnavailable(Exception):
    pass


class AiService:
    def __init__(self, settings: Settings, cache: SqliteCache, store: IncidentStore, loki,
                 gemini: GeminiClient | None, ti=None, levels=None) -> None:
        self.s = settings
        self.cache = cache
        self.store = store
        self.loki = loki
        self.gemini = gemini
        self.ti = ti
        self.levels = levels  # SigmaLevels: 훅 설명에 경고 단계를 붙인다
        self._locks: dict[str, asyncio.Lock] = {}

    async def _events(self, inc: Incident) -> list[TetragonEvent]:
        return await incident_events(self.store, self.loki, self.s, inc)

    async def refresh_allowed(self) -> bool:
        bucket = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M")
        return await self.cache.incr("ai_refresh", bucket) <= self.s.ai_refresh_per_min

    async def cached(self, trace_id: str) -> dict | None:
        """저장된 분석(만료 전). Gemini를 부르지 않는다."""
        hit = await self.cache.get("ai", trace_id)
        return hit.value if hit is not None and not hit.expired else None

    async def analyze(self, inc: Incident, refresh: bool = False) -> dict:
        if not refresh:
            hit = await self.cache.get("ai", inc.trace_id)
            if hit is not None and not hit.expired:
                return hit.value
        if self.gemini is None:
            raise AiUnavailable("GEMINI_API_KEY 또는 GEMINI_MODEL이 없습니다")
        lock = self._locks.setdefault(inc.trace_id, asyncio.Lock())
        async with lock:
            if not refresh:  # 기다리는 동안 다른 요청이 만들었을 수 있다
                hit = await self.cache.get("ai", inc.trace_id)
                if hit is not None and not hit.expired:
                    return hit.value
            tz = self.s.display_tz
            events = await self._events(inc)
            masker = Masker(inc, sorted({e.policy for e in events if e.policy}))
            rows = event_rows(events, tz, int(self.s.dedup_gap_sec * NS), masker)
            lines = [r["display"] for r in rows]  # 화면 근거는 원래 줄 (같은 E 번호)
            ti = None
            if self.ti is not None and inc.src_ip:
                try:
                    ti = await self.ti.lookup(inc.src_ip, allow_fetch=False)
                except ValueError:
                    ti = None  # 사설 IP는 TI 조회 대상이 아니다
            prompt = build_prompt(inc, rows, ti, tz, masker, self.levels.tetragon if self.levels else None)
            raw = None
            for attempt in range(2):  # 해석 실패 시 1회 재시도
                try:
                    raw = await self.gemini.generate_json(SYSTEM, prompt, SCHEMA)
                    break
                except GeminiError as e:
                    log.warning("Gemini 실패(%d): %s", attempt + 1, e)
                    if attempt == 0:
                        await asyncio.sleep(RETRY_WAIT_SEC)  # 503(일시적 과부하)·429는 잠깐 뒤 다시 하면 대개 된다
                    if attempt == 1:
                        stale = await self.cache.get("ai", inc.trace_id)
                        if stale is not None:
                            return stale.value
                        raise
            d = finalize(raw, lines)
            d.update(trace_id=inc.trace_id, model=self.gemini.model, created_ms=int(time.time() * 1000),
                     cached_at=fmt_hms(int(time.time() * 1000), tz), disclaimer=DISCLAIMER, input_lines=len(lines))
            d["markdown"] = render_markdown(d)
            await self.cache.set("ai", inc.trace_id, d, self.s.ai_cache_ttl_days * 86400)
            return d
