# MasPassword for Android

Native Android client (Kotlin, Views) for the MasPassword zero-knowledge
password manager. Read-only by design: browse vaults, search, copy
credentials, live TOTP codes, and fill logins system-wide through the Android
Autofill framework. All decryption happens on the phone; the server only ever
sees ciphertext.

This directory ships as **source**. There are no binary artifacts in the repo
(no wrapper JAR, no PNGs — even the launcher icon is vector XML).

## Modules

```
android/
├── core/    Pure-JVM Kotlin library — NO Android dependencies.
│            Everything security-critical lives here and is unit-tested:
│            crypto, TOTP, QR-payload parsing, domain matching, JSON models.
└── app/     Android app — UI, networking, Keystore storage, AutofillService.
             Contains no crypto of its own; it only calls :core.

┌────────────────────────────  :app  ────────────────────────────┐
│  ui/Link  ui/Unlock  ui/Home  ui/ItemDetail   autofill/Service │
│      │         │        │         │                 │          │
│      └────┬────┴────────┴────┬────┴───────┬─────────┘          │
│       SecureStore        Session (RAM)  VaultRepository        │
│      (Keystore-encrypted  keys+plaintext  (HttpURLConnection)  │
│       prefs: srv/email/   cache, wiped                         │
│       device token)       on lock/death)                       │
└───────────────┬──────────────────┬─────────────┬───────────────┘
                ▼                  ▼             ▼
┌────────────────────────────  :core  ───────────────────────────┐
│ VaultCrypto (PBKDF2, AES-GCM)   RsaKeys (JWK, RSA-OAEP)        │
│ Totp (RFC 6238)  QrPayload  Domains (eTLD+1)  ItemData         │
│ ApiModels (server JSON)          — JUnit tests for all of it — │
└────────────────────────────────────────────────────────────────┘
```

| Requirement | Where |
|---|---|
| Key derivation, AES-GCM envelope | `core/.../VaultCrypto.kt` |
| Private-key JWK import, RSA-OAEP unwrap | `core/.../RsaKeys.kt` |
| TOTP (RFC 6238) | `core/.../Totp.kt` |
| QR pairing payload | `core/.../QrPayload.kt` |
| Registrable-domain matching | `core/.../Domains.kt` |
| Item JSON model | `core/.../ItemData.kt` |
| Server response shapes | `core/.../ApiModels.kt` |
| Link flow (scan/paste + verify) | `app/.../ui/LinkActivity.kt` |
| Master-password unlock | `app/.../ui/UnlockActivity.kt` |
| Vault list + search | `app/.../ui/HomeActivity.kt` |
| Detail, copy, reveal, live TOTP | `app/.../ui/ItemDetailActivity.kt` |
| Autofill service + parsing + auth | `app/.../autofill/*` |
| Token storage (Keystore) | `app/.../SecureStore.kt` |
| RAM-only key holder | `app/.../Session.kt` |
| HTTP (device-token bearer) | `app/.../net/ApiClient.kt` |

## The zero-knowledge model on Android

Identical to the web client (`web/crypto.js`) — byte-for-byte compatible
formats, verified by tests against ciphertexts produced by the actual web
implementation:

- **Key derivation** — PBKDF2-HMAC-SHA256, 600 000 iterations, salt =
  UTF-8 `"vault-internal:" + email`, 256-bit AES key. The email used is the
  account's canonical email from `GET /api/auth/session` (the same string the
  web client used when it encrypted the private key).
- **Envelope** — AES-256-GCM; every stored blob is
  `base64( IV(12 bytes) ‖ ciphertext ‖ GCM tag(16 bytes) )`.
- **Account keypair** — RSA-OAEP-4096 / SHA-256. The private key is stored
  server-side as a **JWK JSON string** encrypted with the derived key
  (`encrypted_private_key`). Decrypting it successfully is the master
  password check — there is no other password verification anywhere.
- **Vaults** — personal vaults (`team_id == null`) encrypt items with the
  **derived key itself**; shared vaults have a random AES-256 key, delivered
  RSA-OAEP-wrapped by `GET /api/vaults/:id/key` and unwrapped locally.

What lives where:

| Data | Location | Survives process death |
|---|---|---|
| Server URL, account email, device token (`mpd_…`) | EncryptedSharedPreferences (master key in Android Keystore, non-exportable) | yes |
| Master password | nowhere — asked, used, discarded | no |
| Derived AES key, RSA private key, vault keys | `Session` (process RAM only) | **no — by design** |
| Decrypted items | `Session` snapshot (RAM only) | no |
| Plaintext of anything | never leaves the device | — |

The device token authenticates the device to the API; it contains **no key
material**. Someone who steals the phone and the token can download
ciphertext, not decrypt it. Biometrics only *gate access* to keys already in
RAM (convenience re-entry); after the process dies the master password is
required again — a fingerprint cannot re-derive a key that no longer exists.

## Building

Requirements: JDK 17+, Android SDK (API 34). No Gradle wrapper JAR is
committed — bootstrap it once with any locally installed Gradle (8.x):

```bash
cd android
gradle wrapper --gradle-version 8.7   # generates gradle/wrapper/gradle-wrapper.jar
./gradlew assembleDebug               # app/build/outputs/apk/debug/app-debug.apk
./gradlew :core:test                  # pure-JVM unit tests (no device/emulator)
```

Or simply open `android/` in Android Studio (Hedgehog or newer), which
provisions Gradle itself, and Run.

Install the debug APK on a device/emulator (API 26+):

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

### Running the :core tests without an Android SDK

`:core` is a plain Kotlin JVM module, so its tests also run with nothing but
a JDK and `kotlinc` + JUnit jars — that is exactly how this code was
validated when it was written (see `core/build.gradle.kts` for the
dependencies: junit 4.13.2 and org.json, which the Android platform provides
at runtime but tests need from Maven).

### Regenerating test vectors

The constants in `core/src/test/.../WebVectors.kt` were produced by running
the **real** `web/crypto.js` under Node's WebCrypto:

```bash
node android/core/scripts/gen-web-vectors.mjs > vectors.json
```

Any run yields valid vectors (IVs and the RSA keypair are random). The tests
prove the Android implementation decrypts what the web client encrypts —
PBKDF2 output, item blobs, the private-key JWK, the OAEP-wrapped vault key
and a shared-vault item, plus the exact QR payload encoding.

## Linking a phone (QR flow)

1. In the **web vault**: Menu → Linked devices → name the device → a QR is
   shown, plus the one-time `mpd_…` token as text.
2. In the app: **Scan QR code** (or paste the code / raw token — with a raw
   token you also type the server URL). The QR payload is
   `base64url(JSON {v:1, srv, email, tok})` and carries **no key material**.
3. Enter the master password **once**. The app calls
   `GET /api/auth/session` with the token, derives the key, and proves the
   password by decrypting `encrypted_private_key`. Wrong password = GCM tag
   failure = clear error; nothing is stored until this succeeds.
4. Server/email/token are then saved (Keystore-encrypted); the derived key
   stays in RAM. Optional: enable *Require biometrics on open* in the menu.

Revoke a phone at any time from the web (Linked devices → revoke); the app
detects the 401 and drops back to the link screen.

## Enabling system autofill

Settings → Passwords & accounts (on some OEMs: System → Languages & input) →
**Autofill service** → MasPassword. The service can also be reached from the
gear icon next to the service entry, which opens the app.

How filling works:

- **Locked** (first use after boot / process death): suggestions show a
  single "Unlock MasPassword" entry → master password dialog → matching
  logins are offered.
- **Unlocked, browser page**: items whose saved URL shares the page's
  **registrable domain** (eTLD+1) appear by name; tapping one asks for
  biometric / device-credential confirmation before the values are released.
  Matching is the same fail-closed logic as the Chrome extension
  (`:core Domains`, ported from `extension/domain.js`):
  `paypal.com.attacker.com` never matches `paypal.com`, unparseable input
  matches nothing.
- **Native apps**: package names are deliberately **not** mapped to domains
  (a sideloaded app can claim any package name), so nothing is auto-offered;
  a "Search MasPassword" entry opens a manual picker instead.

### Autofill limitations (honest list)

- **No SaveInfo**: the app is a read-only client, so Android will never show
  a "save this password in MasPassword?" bar. Create items in the web vault.
- **First unlock needed**: after a reboot or once Android kills the process,
  keys are gone (by design); the first fill of the day goes through the
  master-password dialog.
- **Browser support varies**: suggestions require the browser to expose the
  page via the Autofill framework with `webDomain` (Chrome's
  "Autofill with Google/other services" / compat mode). Browsers that only
  offer their built-in manager will not query third-party services.
- **Field detection is heuristic** beyond `autofillHints`: input types and
  id/hint keywords (see `ParsedStructure.kt`). Exotic login forms may not be
  detected; nothing is ever filled into fields that were not detected.
- **Datasets are capped at 5** matches per request (framework UI gets
  unwieldy beyond that).
- The values inside a returned `Dataset` transit the OS autofill framework
  to the target app — that is inherent to system autofill itself.

## Server / IAP caveat

The app talks to the same REST API as the web client, authenticated with
`Authorization: Bearer mpd_…` (see `internal/middleware/device.go`; device
tokens take priority over JWT/IAP auth).

**An IAP-fronted deployment blocks non-browser clients.** Google Cloud IAP
intercepts every request *before* it reaches the Go server and 302-redirects
to a Google login page — the device token never gets a chance to speak. The
current test deployment (Cloud Run behind IAP) therefore cannot be used by
this app as-is. Options:

- expose a **non-IAP ingress** for `/api/*` (e.g. a separate Cloud Run
  service/tag or load-balancer path that bypasses IAP and relies on device
  tokens + JWT, which the server already enforces), or
- put **IAP programmatic authorization** in front: teach the app to obtain a
  Google OIDC token for the IAP client ID and send it alongside the device
  token (not implemented — it drags Google Sign-In into an otherwise
  self-contained client), or
- run the server reachable directly (self-hosted / docker-compose / any
  plain HTTPS ingress) — works today with no changes.

The app detects the IAP pattern (3xx on an API call, or HTML instead of
JSON) and shows an explicit error pointing here. Plain HTTP is refused by
Android except to `10.0.2.2`/`localhost` (emulator development against
`go run ./cmd/server`, see `res/xml/network_security_config.xml`).

## Design decisions

- **Views over Compose**: fewer dependencies, no compiler plugin, layouts
  reviewable as plain XML — this codebase optimizes for auditability.
- **HttpURLConnection over OkHttp**, **org.json over kotlinx-serialization**
  (platform-provided), **single executor over coroutines**: same reason. The
  only third-party runtime dependencies are androidx, Material, and
  `zxing-android-embedded` (QR scanning; chosen over ML Kit because it needs
  no Google Play Services and is fully open source).
- **`minSdk 26`**: floor for both `AutofillService` and `java.util.Base64`.
- **No screenshots blocked (`FLAG_SECURE`) yet**: the autofill picker must
  render over other apps and secure-flag interactions with the framework
  dialogs are OEM-flaky; revisit deliberately rather than default-on.
- **Backups disabled** (`allowBackup=false`): the Keystore master key would
  not restore anyway; better to re-link explicitly on a new device.
