"""Settings, all from the environment. Nothing is read from or written to disk except the two key files."""

import os
from dataclasses import dataclass, field


def _on(name: str, default: str = "off") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "on", "true", "yes")


def _list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


@dataclass
class Config:
    # Apple Push Notification service: a token signing key (.p8) from the Apple developer account.
    apns_key_file: str = field(default_factory=lambda: os.environ.get("APNS_KEY_FILE", ""))
    apns_key_id: str = field(default_factory=lambda: os.environ.get("APNS_KEY_ID", ""))
    apns_team_id: str = field(default_factory=lambda: os.environ.get("APNS_TEAM_ID", ""))
    # The apps' bundle IDs this relay may send to. The first is used when a request names none.
    apns_topics: list[str] = field(default_factory=lambda: _list("APNS_TOPICS"))
    # Firebase Cloud Messaging (Android): a service account key (JSON) of the Firebase project.
    fcm_service_account_file: str = field(default_factory=lambda: os.environ.get("FCM_SERVICE_ACCOUNT_FILE", ""))
    # Off by default. On: one line per delivery on standard output (time, platform, a short hash of the device
    # token, size, result). Never the message, which the relay cannot read anyway. For testing only.
    delivery_log: bool = field(default_factory=lambda: _on("RELAY_DELIVERY_LOG"))
    # Optional: only callers with one of these keys (Authorization: Bearer <key>) may send.
    access_keys: list[str] = field(default_factory=lambda: _list("RELAY_ACCESS_KEYS"))
    # Rate limits, kept in memory only.
    per_ip_per_minute: int = field(default_factory=lambda: int(os.environ.get("RELAY_PER_IP_PER_MINUTE", "240")))
    per_device_per_minute: int = field(default_factory=lambda: int(os.environ.get("RELAY_PER_DEVICE_PER_MINUTE", "30")))
    source_url: str = field(
        default_factory=lambda: os.environ.get("RELAY_SOURCE_URL", "https://github.com/norjms/openprinthq-push-relay")
    )

    @property
    def apns_ready(self) -> bool:
        return bool(self.apns_key_file and self.apns_key_id and self.apns_team_id and self.apns_topics)

    @property
    def fcm_ready(self) -> bool:
        return bool(self.fcm_service_account_file)
