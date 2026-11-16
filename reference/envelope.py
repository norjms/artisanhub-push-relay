"""Reference implementation of the push envelope (version 1). The hub seals, the phone opens; the relay does
neither. Kept here so every implementation can be checked against the same test vectors.

    envelope = 0x01 || ephemeral X25519 public key (32) || nonce (12) || ChaCha20-Poly1305 ciphertext and tag
    key      = HKDF-SHA256(ikm = X25519(ephemeral private, device public),
                           salt = ephemeral public || device public, info = "artisanhub-push-v1", length 32)

The whole envelope is base64url without padding. The plaintext is UTF-8 JSON.
"""

import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"artisanhub-push-v1"
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key(shared: bytes, eph_pub: bytes, dev_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + dev_pub, info=INFO).derive(shared)


def seal(
    device_public: bytes, message: dict, *, _eph: X25519PrivateKey | None = None, _nonce: bytes | None = None
) -> str:
    eph = _eph or X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(*RAW)
    key = _key(eph.exchange(X25519PublicKey.from_public_bytes(device_public)), eph_pub, device_public)
    nonce = _nonce or os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, json.dumps(message, separators=(",", ":")).encode(), None)
    return b64e(b"\x01" + eph_pub + nonce + ct)


def open_(device_private: X25519PrivateKey, envelope: str) -> dict:
    raw = b64d(envelope)
    if raw[0] != 1:
        raise ValueError("unknown envelope version")
    eph_pub, nonce, ct = raw[1:33], raw[33:45], raw[45:]
    dev_pub = device_private.public_key().public_bytes(*RAW)
    key = _key(device_private.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, dev_pub)
    return json.loads(ChaCha20Poly1305(key).decrypt(nonce, ct, None))
