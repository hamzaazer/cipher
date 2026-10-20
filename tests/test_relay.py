import base64
import threading

import pytest
from fastapi.testclient import TestClient

import main as relay_main
from settings import Settings
from store import MemoryStore


def _settings(**kw) -> Settings:
    base = dict(
        database_url="postgresql://x/x",
        ttl_seconds=60,
        invite_ttl_seconds=120,
        sweeper_interval_seconds=0,
        max_payload_bytes=1024,
        play_integrity_required=False,
        play_integrity_package="dev.cipher.cipher",
        play_integrity_credentials="",
        test_profile=True,
        invite_rate_limit=0,
    )
    base.update(kw)
    return Settings(**base)


@pytest.fixture()
def client():
    store = MemoryStore()
    app = relay_main.create_app(_settings(), store=store)
    with TestClient(app) as c:
        yield c, store


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


INVITE_ID = "aa" * 32


def test_invite_is_one_time(client):
    c, _ = client
    r = c.post(
        "/v1/invite", json={"invite_id": INVITE_ID, "payload": _b64(b"invite")}
    )
    assert r.status_code == 201
    body = r.json()
    assert body["invite_id"] == INVITE_ID
    assert body["ttl"] == 120

    first = c.get(f"/v1/invite/{body['invite_id']}")
    assert first.status_code == 200
    assert base64.b64decode(first.json()["payload"]) == b"invite"
    assert c.get(f"/v1/invite/{body['invite_id']}").status_code == 404


def test_invite_id_must_be_32_bytes(client):
    c, _ = client
    assert (
        c.post("/v1/invite", json={"invite_id": "aa" * 16, "payload": _b64(b"x")}).status_code
        == 404
    )
    assert (
        c.post("/v1/invite", json={"invite_id": "zz", "payload": _b64(b"x")}).status_code
        == 404
    )


def test_duplicate_invite_is_rejected(client):
    c, _ = client
    body = {"invite_id": INVITE_ID, "payload": _b64(b"x")}
    assert c.post("/v1/invite", json=body).status_code == 201
    assert c.post("/v1/invite", json=body).status_code == 409


def test_invite_expiry(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(relay_main, "_now", lambda: 1000)
    invite = c.post(
        "/v1/invite", json={"invite_id": INVITE_ID, "payload": _b64(b"x")}
    ).json()
    monkeypatch.setattr(relay_main, "_now", lambda: 1000 + 121)
    assert c.get(f"/v1/invite/{invite['invite_id']}").status_code == 404


def test_deposit_drain_ack(client):
    c, _ = client
    mailbox = "11" * 16
    r = c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"hello")})
    assert r.status_code == 201
    envelope_id = r.json()["envelope_id"]

    drained = c.get(f"/v1/mailbox/{mailbox}").json()
    assert len(drained["envelopes"]) == 1
    assert base64.b64decode(drained["envelopes"][0]["payload"]) == b"hello"

    assert c.delete(f"/v1/mailbox/{mailbox}/{envelope_id}").status_code == 204
    assert c.get(f"/v1/mailbox/{mailbox}").json()["envelopes"] == []


def test_ack_wrong_mailbox_is_not_found(client):
    c, _ = client
    first = "11" * 16
    second = "22" * 16
    envelope_id = c.post(f"/v1/mailbox/{first}", json={"payload": _b64(b"x")}).json()["envelope_id"]
    assert c.delete(f"/v1/mailbox/{second}/{envelope_id}").status_code == 404


def test_mailbox_cap_blocks_unbounded_storage():
    app = relay_main.create_app(
        _settings(max_envelopes_per_mailbox=2), store=MemoryStore()
    )
    with TestClient(app) as c:
        mailbox = "77" * 16
        assert c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x")}).status_code == 201
        assert c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x")}).status_code == 201
        assert c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x")}).status_code == 429


def test_deposit_ttl_is_bounded(client):
    c, _ = client
    mailbox = "88" * 16
    assert (
        c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x"), "ttl": 30}).status_code
        == 201
    )
    assert (
        c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x"), "ttl": 999999}).status_code
        == 400
    )
    assert (
        c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x"), "ttl": 0}).status_code
        == 400
    )


def test_purge_mailbox(client):
    c, store = client
    mailbox = "33" * 16
    for _ in range(3):
        assert c.post(f"/v1/mailbox/{mailbox}", json={"payload": _b64(b"x")}).status_code == 201
    assert c.delete(f"/v1/mailbox/{mailbox}").json()["deleted"] == 3
    assert c.get(f"/v1/mailbox/{mailbox}").json()["envelopes"] == []


def test_bad_ids_and_payloads(client):
    c, _ = client
    assert c.get("/v1/invite/zz").status_code == 404
    assert c.get("/v1/mailbox/00").status_code == 404
    assert (
        c.post("/v1/invite", json={"invite_id": "bb" * 32, "payload": "***"}).status_code
        == 400
    )
    big = _b64(b"a" * 5000)
    assert (
        c.post("/v1/invite", json={"invite_id": "cc" * 32, "payload": big}).status_code
        == 413
    )
    assert c.post(f"/v1/mailbox/{'44'*16}", json={"payload": big}).status_code == 413


def test_request_size_guard(client):
    c, _ = client
    r = c.post(
        "/v1/mailbox/" + "44" * 16,
        content=b"x" * (40 * 1024),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413


def test_rate_limit():
    app = relay_main.create_app(_settings(invite_rate_limit=2), store=MemoryStore())
    with TestClient(app) as c:
        assert (
            c.post(
                "/v1/invite", json={"invite_id": "01" * 32, "payload": _b64(b"x")}
            ).status_code
            == 201
        )
        assert (
            c.post(
                "/v1/invite", json={"invite_id": "02" * 32, "payload": _b64(b"x")}
            ).status_code
            == 201
        )
        assert (
            c.post(
                "/v1/invite", json={"invite_id": "03" * 32, "payload": _b64(b"x")}
            ).status_code
            == 429
        )


def test_integrity_fails_closed_when_not_configured():
    settings = _settings(play_integrity_required=True, play_integrity_credentials="")
    app = relay_main.create_app(settings, store=MemoryStore())
    with TestClient(app) as c:
        assert (
            c.post(
                "/v1/invite", json={"invite_id": INVITE_ID, "payload": _b64(b"x")}
            ).status_code
            == 503
        )


class FakeVerifier:
    def __init__(self, ok: bool) -> None:
        self.ok = ok
        self.calls = []

    def verify(self, token: str, nonce: str) -> bool:
        self.calls.append((token, nonce))
        return self.ok


def test_integrity_verifier_is_used_only_for_invites():
    verifier = FakeVerifier(False)
    settings = _settings(play_integrity_required=True)
    app = relay_main.create_app(settings, store=MemoryStore(), integrity=verifier)
    with TestClient(app) as c:
        assert (
            c.post(
                "/v1/invite", json={"invite_id": INVITE_ID, "payload": _b64(b"x")}
            ).status_code
            == 403
        )
        assert verifier.calls == [("", "")]
        verifier.ok = True
        assert (
            c.post(
                "/v1/invite",
                json={
                    "invite_id": "dd" * 32,
                    "payload": _b64(b"x"),
                    "integrity_token": "t",
                    "integrity_nonce": "n",
                },
            ).status_code
            == 201
        )
        assert verifier.calls[-1] == ("t", "n")
        # Deposits do not require a token.
        assert c.post(f"/v1/mailbox/{'55'*16}", json={"payload": _b64(b"x")}).status_code == 201


def test_security_headers(client):
    c, _ = client
    r = c.post("/v1/invite", json={"payload": _b64(b"x")})
    assert "no-store" in r.headers["cache-control"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_memory_store_redeem_is_atomic():
    store = MemoryStore()
    store.put_invite(b"i" * 16, b"payload", 0, 100)
    results = []
    threads = [
        threading.Thread(target=lambda: results.append(store.redeem_invite(b"i" * 16, 50)))
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for r in results if r is not None) == 1


def test_sweeper_ttl(client, monkeypatch):
    c, store = client
    monkeypatch.setattr(relay_main, "_now", lambda: 1000)
    c.post(f"/v1/mailbox/{'66'*16}", json={"payload": _b64(b"x")})
    assert store.sweep(1000 + 61) == (0, 1)
    assert c.get(f"/v1/mailbox/{'66'*16}").json()["envelopes"] == []
