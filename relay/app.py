"""OpenPrintHQ push relay.

A hub cannot reach Apple or Google's push services itself (only the app maker's keys can), so it hands each
alert to this relay, which passes it on. The alert is encrypted on the hub with a key that only the phone has
(see docs/encryption.md); the relay only ever sees the device's push token and sealed bytes. It keeps nothing:
no database, no files, no request log. Counters for rate limits live in memory and are lost on restart.
"""

import base64
import binascii
import hashlib
import json
import re
import sys
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .apns import Apns
from .config import Config

MAX_SEALED = 3000  # characters of base64; APNs allows 4 KB for the whole payload
APNS_TOKEN = re.compile(r"^[0-9a-fA-F]{64,200}$")
FCM_TOKEN = re.compile(r"^[A-Za-z0-9_:\-]{20,4096}$")


class SendBody(BaseModel):
    platform: str = Field(pattern="^(apns|fcm)$")
    token: str = Field(max_length=4096)
    sealed: str = Field(max_length=MAX_SEALED)
    urgent: bool = False
    # An opaque tag so a newer message replaces an older one on the phone. The hub sends a hash, never a name.
    collapse: str | None = Field(default=None, max_length=64, pattern="^[A-Za-z0-9_-]*$")
    apns_env: str = Field(default="production", pattern="^(production|sandbox)$")
    apns_topic: str | None = Field(default=None, max_length=200)


class Limiter:
    """Sliding one-minute windows, in memory."""

    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if len(self.hits) > 50_000:  # forget idle keys
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > 60]:
                del self.hits[k]
        return True


def create_app(cfg: Config | None = None, apns=None, fcm=None) -> FastAPI:
    cfg = cfg or Config()
    app = FastAPI(title="OpenPrintHQ push relay", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    if apns is None and cfg.apns_ready:
        apns = Apns(cfg)
    if fcm is None and cfg.fcm_ready:
        from .fcm import Fcm

        fcm = Fcm(cfg)
    limiter = Limiter()
    counts = {"sent": 0, "gone": 0, "failed": 0}

    def _log(platform: str, token: str, size: int, result: str, ms: float):
        if not cfg.delivery_log:
            return
        line = {
            "t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "platform": platform,
            "device": hashlib.sha256(token.encode()).hexdigest()[:12],
            "bytes": size,
            "result": result,
            "ms": round(ms),
        }
        sys.stdout.write(json.dumps(line) + "\n")
        sys.stdout.flush()

    @app.get("/status")
    def status():
        return {
            "service": "openprinthq-push-relay",
            "version": __version__,
            "apns": bool(apns),
            "fcm": bool(fcm),
            "delivery_log": cfg.delivery_log,
            "stores": "nothing: no database, no files, no request log",
            "encryption": "end to end: X25519, HKDF-SHA256, ChaCha20-Poly1305; the relay has no key",
            "access_key_required": bool(cfg.access_keys),
            "source": cfg.source_url,
        }

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/v1/send")
    async def send(body: SendBody, request: Request):
        if cfg.access_keys:
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer ") or auth[7:].strip() not in cfg.access_keys:
                raise HTTPException(401, "access key needed")
        ip = request.client.host if request.client else "?"
        if not limiter.allow("ip:" + ip, cfg.per_ip_per_minute):
            raise HTTPException(429, "too many messages from this address")
        if not limiter.allow("dev:" + hashlib.sha256(body.token.encode()).hexdigest(), cfg.per_device_per_minute):
            raise HTTPException(429, "too many messages to this device")
        try:
            raw = base64.urlsafe_b64decode(body.sealed + "=" * (-len(body.sealed) % 4))
        except (binascii.Error, ValueError):
            raise HTTPException(422, "sealed must be base64url") from None
        if len(raw) < 1 + 32 + 12 + 16 or raw[0] != 1:
            raise HTTPException(422, "sealed is not a version 1 envelope")
        if body.platform == "apns":
            if not apns:
                raise HTTPException(503, "this relay has no Apple key")
            if not APNS_TOKEN.match(body.token):
                raise HTTPException(422, "not an APNs device token")
        else:
            if not fcm:
                raise HTTPException(503, "this relay has no Firebase key")
            if not FCM_TOKEN.match(body.token):
                raise HTTPException(422, "not an FCM registration token")
        t0 = time.monotonic()
        try:
            if body.platform == "apns":
                result, code = await apns.send(
                    body.token,
                    body.sealed,
                    topic=body.apns_topic,
                    env=body.apns_env,
                    urgent=body.urgent,
                    collapse=body.collapse,
                )
            else:
                result, code = await fcm.send(body.token, body.sealed, urgent=body.urgent, collapse=body.collapse)
        except Exception as e:  # noqa: BLE001
            result, code = f"failed:{type(e).__name__}", 502
        _log(body.platform, body.token, len(raw), result, (time.monotonic() - t0) * 1000)
        counts[result.split(":")[0]] += 1
        if code == 200:
            return {"ok": True}
        if code == 410:
            return JSONResponse({"ok": False, "gone": True}, status_code=410)
        return JSONResponse({"ok": False, "error": result.split(":", 1)[-1]}, status_code=502)

    @app.get("/v1/counts")
    def get_counts():
        """Totals since the relay started (no per-device or per-hub numbers)."""
        return dict(counts)

    return app
