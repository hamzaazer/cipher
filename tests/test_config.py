import json

import config


def test_test_profile_requires_both_flags(monkeypatch):
    monkeypatch.delenv("CIPHER_TEST_PROFILE", raising=False)
    monkeypatch.delenv("CIPHER_ENV", raising=False)
    assert not config.test_profile()
    assert config.ttl_seconds() == 86_400

    monkeypatch.setenv("CIPHER_TEST_PROFILE", "1")
    assert not config.test_profile()

    monkeypatch.setenv("CIPHER_ENV", "test")
    assert config.test_profile()
    assert config.ttl_seconds() == 5


def test_packaged_relay_config_is_used(tmp_path, monkeypatch):
    path = tmp_path / "relay_config.json"
    path.write_text(
        json.dumps({"url": "https://relay.test", "pins": ["pin-a", "pin-b"]})
    )
    monkeypatch.setattr(config, "_PACKAGED_CONFIG", path)
    monkeypatch.delenv("CIPHER_RELAY_URL", raising=False)
    monkeypatch.delenv("CIPHER_RELAY_PINS", raising=False)
    assert config.relay_url() == "https://relay.test"
    assert config.relay_pins() == ("pin-a", "pin-b")

    monkeypatch.setenv("CIPHER_RELAY_URL", "https://env.test")
    monkeypatch.setenv("CIPHER_RELAY_PINS", "env-pin")
    assert config.relay_url() == "https://env.test"
    assert config.relay_pins() == ("env-pin",)


def test_packaged_config_tolerates_utf8_bom(tmp_path, monkeypatch):
    path = tmp_path / "relay_config.json"
    payload = json.dumps({"url": "https://relay.test", "pins": ["pin-a"]})
    path.write_bytes(b"\xef\xbb\xbf" + payload.encode("utf-8"))
    monkeypatch.setattr(config, "_PACKAGED_CONFIG", path)
    monkeypatch.delenv("CIPHER_RELAY_URL", raising=False)
    monkeypatch.delenv("CIPHER_RELAY_PINS", raising=False)
    assert config.relay_url() == "https://relay.test"
    assert config.relay_pins() == ("pin-a",)


def test_missing_packaged_config_is_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_PACKAGED_CONFIG", tmp_path / "absent.json")
    monkeypatch.delenv("CIPHER_RELAY_URL", raising=False)
    monkeypatch.delenv("CIPHER_RELAY_PINS", raising=False)
    assert config.relay_url() == "https://relay.cipher.invalid"
    assert config.relay_pins() == ()
