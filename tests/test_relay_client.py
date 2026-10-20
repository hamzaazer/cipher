import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from relay_client import (
    PinMismatch,
    RelayClient,
    RelayNotFound,
    RelayRateLimited,
    pin_matches,
    spki_sha256,
)


def _cert() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_spki_pin_is_stable_and_checked():
    der = _cert()
    pin = spki_sha256(der)
    assert spki_sha256(der) == pin
    assert pin_matches(der, (pin,))
    assert not pin_matches(der, ("A" * 44,))
    assert not pin_matches(der, ())


def test_release_refuses_cleartext(monkeypatch):
    monkeypatch.setenv("CIPHER_ENV", "release")
    with pytest.raises(PinMismatch):
        RelayClient("http://relay.test", ("x",))


def test_release_refuses_unpinned_tls(monkeypatch):
    monkeypatch.setenv("CIPHER_ENV", "release")
    with pytest.raises(PinMismatch):
        RelayClient("https://relay.test", ())


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, n: int) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        return self.handler(request)


def test_client_roundtrip_encodes_opaque_bytes(monkeypatch):
    monkeypatch.setenv("CIPHER_ENV", "test")
    invite_id = "aa" * 32

    def handler(request):
        path = request.full_url.split("test", 1)[1]
        method = request.get_method()
        if method == "POST" and path == "/v1/invite":
            body = json.loads(request.data)
            assert body["invite_id"] == invite_id
            assert base64.b64decode(body["payload"]) == b"invite"
            return FakeResponse(
                b'{"invite_id":"' + invite_id.encode() + b'","expires_at":1,"ttl":120}'
            )
        if method == "GET" and path == f"/v1/invite/{invite_id}":
            return FakeResponse(b'{"payload":"aW52aXRl","expires_at":1}')
        if method == "DELETE" and path == f"/v1/invite/{invite_id}":
            return FakeResponse(b"")
        if method == "POST" and path == "/v1/mailbox/bb":
            body = json.loads(request.data)
            assert base64.b64decode(body["payload"]) == b"msg"
            assert body.get("ttl") == 120
            return FakeResponse(b'{"envelope_id":"cc","expires_at":2}')
        if method == "GET" and path == "/v1/mailbox/bb":
            return FakeResponse(
                b'{"envelopes":[{"envelope_id":"cc","payload":"bXNn",'
                b'"created_at":1,"expires_at":2}]}'
            )
        if method == "DELETE" and path == "/v1/mailbox/bb/cc":
            return FakeResponse(b"")
        if method == "DELETE" and path == "/v1/mailbox/bb":
            return FakeResponse(b'{"deleted":1}')
        raise AssertionError((method, path))

    opener = FakeOpener(handler)
    client = RelayClient("http://relay.test", (), opener=opener)
    assert client.create_invite(b"\xaa" * 32, b"invite")["invite_id"] == invite_id
    assert client.redeem_invite(invite_id) == b"invite"
    client.revoke_invite(invite_id)
    assert client.deposit("bb", b"msg", ttl=120) == "cc"
    envelopes = client.drain("bb")
    assert envelopes[0].payload == b"msg"
    client.ack("bb", "cc")
    assert client.purge("bb") == 1


def test_client_maps_errors(monkeypatch):
    import urllib.error

    monkeypatch.setenv("CIPHER_ENV", "test")

    def not_found(request):
        raise urllib.error.HTTPError(request.full_url, 404, "no", {}, None)

    def limited(request):
        raise urllib.error.HTTPError(request.full_url, 429, "slow", {}, None)

    with pytest.raises(RelayNotFound):
        RelayClient("http://relay.test", (), opener=FakeOpener(not_found)).redeem_invite("x")
    with pytest.raises(RelayRateLimited):
        RelayClient("http://relay.test", (), opener=FakeOpener(limited)).create_invite(
            b"\xaa" * 32, b"x"
        )
