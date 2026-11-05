import httpx
import respx


def test_healthz_no_auth(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_metrics_no_auth(client):
    client.get("/healthz")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert 'tefal_http_requests_total{method="GET",route="/healthz",status="200"}' in r.text


@respx.mock
def test_readyz_ok(client):
    respx.get("http://tempo.test:3200/ready").mock(return_value=httpx.Response(200))
    respx.get("http://loki.test:3100/ready").mock(return_value=httpx.Response(200))
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "tempo": "ok", "loki": "ok", "cache": "ok"}


@respx.mock
def test_readyz_not_ready(client):
    respx.get("http://tempo.test:3200/ready").mock(return_value=httpx.Response(503))
    respx.get("http://loki.test:3100/ready").mock(side_effect=httpx.ConnectError("down"))
    r = client.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert body["tempo"] == "http 503"
    assert body["loki"].startswith("error")
    assert body["cache"] == "ok"


def test_auth_required(client):
    r = client.get("/_probe")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"


def test_auth_wrong_token(client):
    r = client.get("/_probe", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_auth_ok(client, auth):
    r = client.get("/_probe", headers=auth)
    assert r.status_code == 200


def test_not_found_format(client):
    r = client.get("/nope")
    assert r.status_code == 404
    assert set(r.json()) == {"error", "detail"}
