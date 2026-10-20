import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto.mailbox import mailbox_id
from crypto.padding import pad
from crypto.pairing import derive, pair_payload_a, pair_payload_b
from crypto.primitives import public_bytes
from crypto.ratchet import ChainState, seal

OUT = Path(__file__).resolve().parents[1] / "protocol" / "vectors"


def priv(b: int) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes([b]) * 32)


def hx(b: bytes) -> str:
    return b.hex()


def main() -> None:
    secret = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    a = priv(0x11)
    b = priv(0x22)
    keys_a = derive(secret, a, public_bytes(b))
    keys_b = derive(secret, b, public_bytes(a))
    assert keys_a == keys_b
    identity_a = bytes.fromhex("aa" * 32)
    identity_b = bytes.fromhex("bb" * 32)
    pa = pair_payload_a(keys_a, identity_a, public_bytes(a))
    pb = pair_payload_b(keys_b, identity_b, public_bytes(b))
    pairing = {
        "name": "pairing-v1",
        "secret": hx(secret),
        "eph_a_private": hx(bytes([0x11]) * 32),
        "eph_b_private": hx(bytes([0x22]) * 32),
        "eph_a_public": hx(public_bytes(a)),
        "eph_b_public": hx(public_bytes(b)),
        "k_enc": hx(keys_a.k_enc),
        "k_mac": hx(keys_a.k_mac),
        "conv_seed": hx(keys_a.conv_seed),
        "sas": keys_a.sas,
        "identity_a": hx(identity_a),
        "identity_b": hx(identity_b),
        "payload_a": hx(pa),
        "payload_b": hx(pb),
    }
    (OUT / "pairing.json").write_text(json.dumps(pairing, indent=2) + "\n")

    padding = {
        "name": "padding-v1",
        "vectors": [
            {"plaintext": "", "padded_len": len(pad(b"")), "padded": pad(b"").hex()},
            {"plaintext": "00" * 124, "padded_len": len(pad(bytes(124))), "padded": pad(bytes(124)).hex()},
            {
                "plaintext": (b"cipher" * 100).hex(),
                "padded_len": len(pad(b"cipher" * 100)),
                "padded": pad(b"cipher" * 100).hex(),
            },
        ],
    }
    (OUT / "padding.json").write_text(json.dumps(padding, indent=2) + "\n")

    mbx = {
        "name": "mailbox-v1",
        "conv_secret": hx(bytes.fromhex("cc" * 32)),
        "day_epoch": 20000,
        "mailbox_id": hx(mailbox_id(bytes.fromhex("cc" * 32), 20000)),
        "mailbox_id_next_day": hx(mailbox_id(bytes.fromhex("cc" * 32), 20001)),
    }
    (OUT / "mailbox.json").write_text(json.dumps(mbx, indent=2) + "\n")

    # Ratchet vector uses a fixed counter and fixed random padding so the
    # nonce/message key are still deterministic only for message_key material;
    # ciphertext is not a vector because the nonce has 8 random bytes.
    chain = ChainState(bytes.fromhex("dd" * 32), 0)
    mk, nxt = chain.advance()
    ratchet = {
        "name": "ratchet-v1",
        "chain_key": hx(chain.key),
        "index": 0,
        "message_key": hx(mk),
        "next_chain_key": hx(nxt.key),
        "next_index": nxt.index,
    }
    (OUT / "ratchet.json").write_text(json.dumps(ratchet, indent=2) + "\n")
    print("wrote vectors to", OUT)


if __name__ == "__main__":
    main()
