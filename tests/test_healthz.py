from fastapi.testclient import TestClient

from main import create_app
from settings import Settings


def _settings(**kw) -> Settings:
    base = dict(
        database_url="postgresql://x/x",
        ttl_seconds=86400,
        invite_ttl_seconds=120,
        sweeper_interval_seconds=60,
        max_payload_bytes=12288,
        play_integrity_required=True,
        play_integrity_package="dev.cipher.cipher",
        play_integrity_credentials="",
        test_profile=False,
    )
    base.update(kw)
    return Settings(**base)


def test_healthz_returns_200():
    client = TestClient(create_app(_settings()))
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "cipher-relay"
    assert isinstance(body["time"], int)


def test_no_docs_surface():
    client = TestClient(create_app(_settings()))
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
