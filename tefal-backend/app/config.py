"""환경 변수 설정 (BACKEND_API.md 7장)."""

from functools import cached_property

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.demo import parse_pool


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # 인증
    tefal_api_token: SecretStr

    # 내부 데이터 소스
    tempo_url: str = "http://tempo.monitoring.svc:3200"
    tempo_otlp_url: str = "http://tempo.monitoring.svc:4318/v1/traces"
    tempo_export_enabled: bool = True  # 사건 trace 기록 + Beyla 연결
    loki_url: str = "http://loki.monitoring.svc:3100"
    hubble_relay_addr: str = "hubble-relay.kube-system.svc:80"
    hubble_enabled: bool = True
    hubble_timeout_sec: float = 10.0
    loki_falco_selector: str = '{namespace="falco", container="falco"}'
    prometheus_url: str = "http://kube-prometheus-stack-prometheus.monitoring:9090"
    loki_tetragon_selector: str = '{namespace="kube-system", container="export-stdout"}'

    # K8s API (④ 인프라, 5.5). pod의 ServiceAccount 토큰을 쓴다
    k8s_api_url: str = "https://kubernetes.default.svc"
    k8s_enabled: bool = True
    falco_rules_configmap: str = "falco/falco-rules"  # <namespace>/<name>, Falco 커스텀 룰

    # 사건 생성 (4장)
    collector_enabled: bool = True
    collect_interval_sec: float = 5.0
    collect_backfill_hours: float = 24.0  # 커서가 없을 때(첫 기동) 거슬러 읽을 범위
    collect_chunk_sec: int = 3600  # 한 번에 읽는 Loki 구간
    correlate_lookback_sec: int = 60
    correlate_merge_sec: int = 10
    correlate_max_depth: int = 8
    sigma_levels_file: str = "/config/sigma_levels.yaml"

    # Falco (Falcosidekick webhook)
    falco_webhook_token: SecretStr | None = None  # 없으면 /ingest/falco는 503
    falco_min_priority: str = "Warning"
    falco_ignore_loopback: bool = True  # 루프백 연결 경보(Apache dummy connection 등)는 오탐으로 보고 뺀다 (falsepos.py)
    dedup_gap_sec: float = 1.0  # 같은 행위 반복을 1건으로 접는 간격 (dedup.py)
    falco_wait_sec: int = 30

    # 외부 TI / AI (해당 기능 단계에서 필수 검사)
    abuseipdb_api_key: SecretStr | None = None
    abuseipdb_daily_limit: int = 1000
    virustotal_api_key: SecretStr | None = None
    virustotal_daily_limit: int = 500
    virustotal_per_min: int = 4
    geoip_city_db: str = "/data/GeoLite2-City.mmdb"
    geoip_asn_db: str = "/data/GeoLite2-ASN.mmdb"
    ipinfo_token: SecretStr | None = None  # 없으면 ipinfo.io 조회를 건너뛴다
    ipinfo_daily_limit: int = 1500  # 무료 플랜 월 한도를 하루로 나눈 값보다 작게
    gemini_api_key: SecretStr | None = None
    gemini_model: str | None = None

    # 캐시 / 정책
    ti_cache_ttl_hours: int = 24
    ai_cache_ttl_days: int = 7
    ai_refresh_per_min: int = 5
    fp_threshold: int = 5
    cache_db: str = "sqlite:////data/tefal.db"
    watch_namespaces: str = "web"

    # 시연 모드 (core/demo.py). 쉼표로 구분한 공인 IP. 비어 있으면 꺼짐
    demo_src_ip_pool: str = ""

    # 공통
    http_timeout_seconds: float = 5.0
    display_tz: str = "Asia/Seoul"

    @field_validator("demo_src_ip_pool")
    @classmethod
    def _check_demo_pool(cls, v: str) -> str:
        parse_pool(v)  # 잘못된 값이면 기동 시 바로 실패시킨다
        return v

    @cached_property
    def demo_src_ip_list(self) -> list[str]:
        return parse_pool(self.demo_src_ip_pool)

    @field_validator("cache_db")
    @classmethod
    def _check_cache_db(cls, v: str) -> str:
        if not v.startswith("sqlite:///"):
            # Redis는 다중 replica 확장 시 추가 (미결정 사항 4)
            raise ValueError("현재는 sqlite:/// 캐시만 지원합니다")
        return v

    @cached_property
    def cache_db_path(self) -> str:
        # sqlite:////data/tefal.db → /data/tefal.db, sqlite:///./tefal.db → ./tefal.db
        return self.cache_db.removeprefix("sqlite:///")

    @cached_property
    def watch_namespace_list(self) -> list[str]:
        return [n.strip() for n in self.watch_namespaces.split(",") if n.strip()]

    def secret_values(self) -> list[str]:
        """로그 마스킹 대상 비밀값."""
        secrets = [
            self.tefal_api_token,
            self.falco_webhook_token,
            self.abuseipdb_api_key,
            self.virustotal_api_key,
            self.ipinfo_token,
            self.gemini_api_key,
        ]
        return [s.get_secret_value() for s in secrets if s and s.get_secret_value()]
