import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.auth import require_token
from app.main import create_app

TOKEN = "test-token-1234"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        tefal_api_token=TOKEN,
        tempo_url="http://tempo.test:3200",
        loki_url="http://loki.test:3100",
        cache_db=f"sqlite:///{tmp_path / 'tefal.db'}",
        collector_enabled=False,
        watch_namespaces="vuln-lab",
        sigma_levels_file=str(tmp_path / "sigma_levels.yaml"),
        prometheus_url="http://prom.test:9090",
        falco_webhook_token="falco-token-5678",
        k8s_enabled=False,
        hubble_enabled=False,
        _env_file=None,
    )


@pytest.fixture
def app(settings):
    app = create_app(settings)
    # 인증 검사용 더미 라우트
    probe = APIRouter()

    @probe.get("/_probe")
    async def _probe():
        return {"ok": True}

    app.include_router(probe, dependencies=[Depends(require_token)])
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth() -> dict:
    return {"Authorization": f"Bearer {TOKEN}"}
