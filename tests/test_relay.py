import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from reference.envelope import RAW, seal
from relay.app import create_app
from relay.config import Config

TOKEN = "a" * 64


def sealed():
    return seal(X25519PrivateKey.generate().public_key().public_bytes(*RAW), {"t": "Print finished"})


class FakeApns:
    def __init__(self, result=("sent", 200)):
        self.result, self.calls = result, []

    async def send(self, token, sealed, **kw):
        self.calls.append((token, sealed, kw))
        return self.result


def make(cfg=None, apns=None, fcm=None):
    cfg = cfg or Config(apns_topics=["us.artisanprints.hub"])
    return TestClient(create_app(cfg, apns=apns, fcm=fcm))


def test_status_says_what_it_keeps():
    s = make().get("/status").json()
    assert s["delivery_log"] is False
    assert s["stores"].startswith("nothing")
    assert s["source"].startswith("https://")


def test_sends_sealed_bytes_unchanged():
    a = FakeApns()
    env = sealed()
    r = make(apns=a).post("/v1/send", json={"platform": "apns", "token": TOKEN, "sealed": env, "urgent": True})
    assert r.status_code == 200
    assert a.calls[0][1] == env and a.calls[0][2]["urgent"] is True


def test_gone_device_answers_410():
    body = {"platform": "apns", "token": TOKEN, "sealed": sealed()}
    r = make(apns=FakeApns(("gone", 410))).post("/v1/send", json=body)
    assert r.status_code == 410 and r.json()["gone"] is True


def test_rejects_plain_text():
    plain = base64.urlsafe_b64encode(json.dumps({"t": "hello"}).encode()).decode()
    r = make(apns=FakeApns()).post("/v1/send", json={"platform": "apns", "token": TOKEN, "sealed": plain})
    assert r.status_code == 422


def test_no_key_for_platform():
    r = make().post("/v1/send", json={"platform": "fcm", "token": "x" * 40, "sealed": sealed()})
    assert r.status_code == 503


def test_access_key():
    cfg = Config(apns_topics=["t"], access_keys=["k1"])
    c = make(cfg, apns=FakeApns())
    body = {"platform": "apns", "token": TOKEN, "sealed": sealed()}
    assert c.post("/v1/send", json=body).status_code == 401
    assert c.post("/v1/send", json=body, headers={"authorization": "Bearer k1"}).status_code == 200


def test_rate_limit_per_device():
    cfg = Config(apns_topics=["t"], per_device_per_minute=2)
    c = make(cfg, apns=FakeApns())
    body = {"platform": "apns", "token": TOKEN, "sealed": sealed()}
    assert [c.post("/v1/send", json=body).status_code for _ in range(3)] == [200, 200, 429]


@pytest.mark.parametrize("on", [False, True])
def test_delivery_log_only_when_on(on, capsys):
    cfg = Config(apns_topics=["t"], delivery_log=on)
    env = sealed()
    make(cfg, apns=FakeApns()).post("/v1/send", json={"platform": "apns", "token": TOKEN, "sealed": env})
    out = capsys.readouterr().out
    if not on:
        assert out == ""
    else:
        line = json.loads(out.strip())
        assert set(line) == {"t", "platform", "device", "bytes", "result", "ms"}
        assert TOKEN not in out and env not in out


def test_apns_request_shape():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"], seen["headers"], seen["body"] = str(req.url), req.headers, json.loads(req.content)
        return httpx.Response(200)

    import os
    import tempfile

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    k = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with tempfile.NamedTemporaryFile("wb", suffix=".p8", delete=False) as f:
        f.write(k)
    try:
        from relay.apns import Apns

        cfg = Config(apns_key_file=f.name, apns_key_id="KEY", apns_team_id="TEAM", apns_topics=["us.artisanprints.hub"])
        a = Apns(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        env = sealed()
        c = make(cfg, apns=a)
        body = {"platform": "apns", "token": TOKEN, "sealed": env, "collapse": "abc"}
        assert c.post("/v1/send", json=body).status_code == 200
    finally:
        os.unlink(f.name)
    assert seen["url"] == f"https://api.push.apple.com/3/device/{TOKEN}"
    assert seen["headers"]["apns-topic"] == "us.artisanprints.hub"
    assert seen["headers"]["apns-collapse-id"] == "abc"
    assert seen["body"]["e"] == env
    assert seen["body"]["aps"]["mutable-content"] == 1
    assert "Print finished" not in json.dumps(seen["body"])


def test_fcm_unregistered_is_gone(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from relay.fcm import Fcm

    pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )
    sa = tmp_path / "sa.json"
    sa.write_text(
        json.dumps(
            {
                "client_email": "x@y.iam.gserviceaccount.com",
                "private_key": pem,
                "private_key_id": "k",
                "project_id": "proj",
            }
        )
    )

    def handler(req: httpx.Request):
        if req.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        assert req.url.path == "/v1/projects/proj/messages:send"
        body = json.loads(req.content)
        assert body["message"]["data"]["v"] == "1" and "notification" not in body["message"]
        return httpx.Response(404, json={"error": {"status": "NOT_FOUND", "details": [{"errorCode": "UNREGISTERED"}]}})

    cfg = Config(fcm_service_account_file=str(sa))
    f = Fcm(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    r = make(cfg, fcm=f).post("/v1/send", json={"platform": "fcm", "token": "t" * 40, "sealed": sealed()})
    assert r.status_code == 410
