"""Firebase Cloud Messaging (HTTP v1), for Android. Sends data-only messages: the app decrypts and shows them."""

import json
import time

import httpx
import jwt

from .config import Config

TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/firebase.messaging"


class Fcm:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None):
        self.cfg = cfg
        self._client = client
        self._sa: dict | None = None
        self._access: tuple[str, float] | None = None

    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=15)
        return self._client

    def _account(self) -> dict:
        if self._sa is None:
            with open(self.cfg.fcm_service_account_file) as f:
                self._sa = json.load(f)
        return self._sa

    async def _bearer(self) -> str:
        if self._access and time.time() < self._access[1]:
            return self._access[0]
        sa = self._account()
        now = int(time.time())
        assertion = jwt.encode(
            {"iss": sa["client_email"], "scope": SCOPE, "aud": TOKEN_URL, "iat": now, "exp": now + 3600},
            sa["private_key"],
            algorithm="RS256",
            headers={"kid": sa.get("private_key_id")},
        )
        r = await self.client().post(
            TOKEN_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
        )
        r.raise_for_status()
        d = r.json()
        self._access = (d["access_token"], time.time() + int(d.get("expires_in", 3600)) - 300)
        return self._access[0]

    async def send(self, token: str, sealed: str, *, urgent: bool, collapse: str | None) -> tuple[str, int]:
        msg = {
            "token": token,
            "data": {"e": sealed, "v": "1"},
            "android": {"priority": "HIGH" if urgent else "NORMAL", "ttl": "86400s"},
        }
        if collapse:
            msg["android"]["collapse_key"] = collapse[:64]
        url = f"https://fcm.googleapis.com/v1/projects/{self._account()['project_id']}/messages:send"
        r = await self.client().post(
            url, json={"message": msg}, headers={"authorization": f"Bearer {await self._bearer()}"}
        )
        if r.status_code == 200:
            return "sent", 200
        status = _status(r)
        if r.status_code == 404 or status in ("UNREGISTERED", "NOT_FOUND"):
            return "gone", 410
        if r.status_code == 401:
            self._access = None
        return f"failed:{status or r.status_code}", 502


def _status(r: httpx.Response) -> str:
    try:
        err = r.json().get("error") or {}
        for d in err.get("details") or []:
            if d.get("errorCode"):
                return str(d["errorCode"])
        return str(err.get("status") or "")
    except Exception:  # noqa: BLE001
        return ""
