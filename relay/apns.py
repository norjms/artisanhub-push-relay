"""Apple Push Notification service, with a token signing key (no certificates)."""

import time

import httpx
import jwt

from .config import Config

HOSTS = {"production": "https://api.push.apple.com", "sandbox": "https://api.sandbox.push.apple.com"}
# Apple answers these when the device token is no longer valid; the hub should forget that device.
GONE_REASONS = {"BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic", "ExpiredToken"}


class Apns:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None):
        self.cfg = cfg
        self._client = client
        self._key: str | None = None
        self._jwt: tuple[str, float] | None = None

    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(http2=True, timeout=15)
        return self._client

    def _token(self) -> str:
        # Apple accepts a provider token for up to an hour and refuses one refreshed more than every 20 minutes.
        if self._jwt and time.time() - self._jwt[1] < 40 * 60:
            return self._jwt[0]
        if self._key is None:
            with open(self.cfg.apns_key_file) as f:
                self._key = f.read()
        now = time.time()
        tok = jwt.encode(
            {"iss": self.cfg.apns_team_id, "iat": int(now)},
            self._key,
            algorithm="ES256",
            headers={"kid": self.cfg.apns_key_id},
        )
        self._jwt = (tok, now)
        return tok

    async def send(
        self, token: str, sealed: str, *, topic: str | None, env: str, urgent: bool, collapse: str | None
    ) -> tuple[str, int]:
        """Answers (result, status): result is sent, gone or failed:<reason>."""
        topic = topic if topic in self.cfg.apns_topics else self.cfg.apns_topics[0]
        # What Apple and the phone's lock screen see before the app decrypts it: a fixed line, nothing about the
        # alert. The app's notification service extension replaces it with the decrypted title and text.
        body = {
            "aps": {
                "alert": {"title": "OpenPrintHQ", "body": "New update from your hub"},
                "mutable-content": 1,
                "sound": "default",
            },
            "e": sealed,
        }
        headers = {
            "authorization": f"bearer {self._token()}",
            "apns-topic": topic,
            "apns-push-type": "alert",
            "apns-priority": "10" if urgent else "5",
            "apns-expiration": str(int(time.time()) + 86400),
        }
        if collapse:
            headers["apns-collapse-id"] = collapse[:64]
        r = await self.client().post(
            f"{HOSTS.get(env, HOSTS['production'])}/3/device/{token}", json=body, headers=headers
        )
        if r.status_code == 200:
            return "sent", 200
        reason = _reason(r)
        if r.status_code == 410 or reason in GONE_REASONS:
            return "gone", 410
        if reason == "ExpiredProviderToken":
            self._jwt = None
        return f"failed:{reason or r.status_code}", 502


def _reason(r: httpx.Response) -> str:
    try:
        return str(r.json().get("reason") or "")
    except Exception:  # noqa: BLE001
        return ""
