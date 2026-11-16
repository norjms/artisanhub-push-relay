import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from reference.envelope import RAW, b64d, open_, seal

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())


def test_round_trip():
    dev = X25519PrivateKey.generate()
    msg = {"t": "H2D finished Gear housing", "b": "Clear the plate.", "k": "print_done"}
    env = seal(dev.public_key().public_bytes(*RAW), msg)
    assert open_(dev, env) == msg


def test_other_key_cannot_open():
    dev, other = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    env = seal(dev.public_key().public_bytes(*RAW), {"t": "x"})
    try:
        open_(other, env)
    except Exception:  # noqa: BLE001
        return
    raise AssertionError("opened with the wrong key")


def test_vectors():
    for v in VECTORS:
        dev = X25519PrivateKey.from_private_bytes(b64d(v["device_private"]))
        eph = X25519PrivateKey.from_private_bytes(b64d(v["ephemeral_private"]))
        assert seal(b64d(v["device_public"]), v["message"], _eph=eph, _nonce=b64d(v["nonce"])) == v["envelope"]
        assert open_(dev, v["envelope"]) == v["message"]
