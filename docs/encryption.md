# How an alert is encrypted

Each phone makes its own key pair the first time push notifications are turned on. The private key stays in the
phone's secure storage (the iOS Keychain, the Android Keystore-backed encrypted storage) and never leaves it. The
phone gives its hub two things: the public key and the push token Apple or Google gave the app.

For every alert the hub:

1. makes a new, one-time X25519 key pair;
2. combines the one-time private key with the phone's public key (X25519) and turns the result into a 32-byte
   key with HKDF-SHA256 (salt: the one-time public key followed by the phone's public key; info:
   `artisanhub-push-v1`);
3. encrypts the alert (title, text, link, kind, time, as JSON) with ChaCha20-Poly1305 and a random 12-byte nonce;
4. sends `0x01 || one-time public key (32) || nonce (12) || ciphertext and tag` as base64url to the relay, with
   the push token.

The relay passes the sealed bytes to Apple or Google unchanged. Apple, Google and the relay see only that some
device got a message of some size. On iPhone a notification service extension in the app opens the message
before it is shown; until then the notification reads "New update from your hub". On Android the message is
data only, and the app opens it and shows the notification itself.

Without the phone's private key nobody can read the alert, including whoever runs the relay. The one-time key is
thrown away after each alert, so one alert's key says nothing about another's.

`reference/envelope.py` is the reference implementation and `tests/vectors.json` has fixed test vectors that the
hub and both apps are checked against.
