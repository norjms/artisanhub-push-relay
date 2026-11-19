# OpenPrintHQ push relay

Passes OpenPrintHQ alerts to phones through Apple's and Google's push services, without being able to read them
and without keeping anything.

Apple and Google only take push messages from whoever holds the app's signing keys, so a self-hosted hub cannot
reach the OpenPrintHQ app on a phone by itself. The hub encrypts each alert for one phone and hands the sealed bytes
to this relay; the relay hands them to Apple or Google; the app decrypts them on the phone.

## What the relay sees, and what it keeps

| | |
|---|---|
| Sees | a device push token, sealed bytes it has no key for, whether the alert is urgent, an opaque collapse tag, the caller's IP address while the request is open |
| Keeps | nothing: no database, no files, no request log. Rate limit counters live in memory and are gone on restart |
| Delivery log | off unless `RELAY_DELIVERY_LOG=on`. When on, one line per delivery on standard output: time, platform, a 12-character hash of the device token, size, result, time taken. Never the message, never an IP address. Meant for testing; `GET /status` says whether it is on |

How the encryption works: [docs/encryption.md](docs/encryption.md).

## API

- `POST /v1/send` `{"platform": "apns"|"fcm", "token", "sealed", "urgent", "collapse", "apns_env", "apns_topic"}`.
  200 sent; 410 the device is gone (the hub forgets it); 422 not a sealed envelope or not a valid token;
  429 rate limited; 502 Apple or Google refused it; 503 this relay has no key for that platform.
- `GET /status`: version, which platforms it can send to, whether the delivery log is on, where the source is.
- `GET /v1/counts`: messages sent, gone and failed since start, in total.

## Running your own

Anyone can run a relay for their own build of the app: it needs that build's Apple key and Firebase project.

| Variable | |
|---|---|
| `APNS_KEY_FILE`, `APNS_KEY_ID`, `APNS_TEAM_ID` | an Apple Push Notifications key (.p8), its key ID and the developer team ID |
| `APNS_TOPICS` | the app bundle IDs it may send to, comma separated |
| `FCM_SERVICE_ACCOUNT_FILE` | a Firebase project service account key (JSON) |
| `RELAY_DELIVERY_LOG` | `on` to log deliveries (see above); off by default |
| `RELAY_ACCESS_KEYS` | optional: callers must send `Authorization: Bearer <one of these>` |
| `RELAY_PER_IP_PER_MINUTE`, `RELAY_PER_DEVICE_PER_MINUTE` | rate limits, default 240 and 30 |
| `RELAY_SOURCE_URL` | the source link `/status` shows (the AGPL asks for one) |

```sh
docker build -t artisanhub-push-relay .
docker run -d --read-only --cap-drop ALL -p 8080:8080 \
  -v /path/to/keys:/keys:ro -e APNS_KEY_FILE=/keys/AuthKey.p8 -e APNS_KEY_ID=... -e APNS_TEAM_ID=... \
  -e APNS_TOPICS=com.example.app -e FCM_SERVICE_ACCOUNT_FILE=/keys/firebase.json artisanhub-push-relay
```

Put it behind HTTPS. A hub uses it when its push relay address is set to it.

## Development

```sh
pip install -r requirements-dev.txt
ruff check . && ruff format --check . && python -m pytest -q
```

## License

AGPL-3.0-or-later. See LICENSE.
