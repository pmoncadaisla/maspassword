# MasPassword iOS

Native iOS client (SwiftUI, iOS 16+) for the MasPassword zero-knowledge
password manager, plus a **Password AutoFill credential-provider extension**
so logins can be filled system-wide (Safari and apps) with QuickType
suggestions.

```
ios/
├── project.yml                  # XcodeGen spec (generates MasPassword.xcodeproj)
├── MasPasswordCore/             # SwiftPM package: ALL testable logic, no UIKit
│   ├── Package.swift
│   ├── Sources/MasPasswordCore/
│   │   ├── VaultCrypto.swift    # PBKDF2 (protocol + CommonCrypto), AES-GCM (CryptoKit)
│   │   ├── RsaKeys.swift        # SecKey import + RSA-OAEP-SHA256 unwrap (Apple only)
│   │   ├── JwkToDer.swift       # WebCrypto JWK -> PKCS#1 DER (ASN.1 writer)
│   │   ├── PureCrypto.swift     # pure-Swift SHA-1/256, HMAC, PBKDF2 (TOTP + Linux tests)
│   │   ├── Totp.swift           # RFC 6238 (SHA1 / 30 s / 6 digits)
│   │   ├── QrPayload.swift      # pairing-QR parser (+ device-token shape check)
│   │   ├── Domains.swift        # eTLD+1 matching, port of extension/domain.js
│   │   ├── ItemData.swift       # decrypted item model (tolerant Codable)
│   │   ├── ApiModels.swift      # typed parsers for the Go server's JSON
│   │   ├── Base32.swift / Base64URL.swift / Lenient.swift / CryptoError.swift
│   └── Tests/MasPasswordCoreTests/   # XCTest — see "Tests" below
└── MasPassword/
    ├── App/                     # app target sources (SwiftUI)
    │   ├── MasPasswordApp.swift, AppState.swift, ApiClient.swift
    │   └── Views/  (Link/QRScanner/Unlock/Vaults/ItemList/ItemDetail/Settings)
    ├── AutoFill/                # extension target sources
    │   ├── CredentialProviderViewController.swift  # ASCredentialProviderViewController
    │   ├── AutoFillModel.swift, AutoFillRootView.swift
    └── Shared/                  # compiled into BOTH targets
        ├── KeychainStore.swift  # linked account, shared keychain group
        ├── SharedCache.swift    # encrypted vault cache in the App Group
        ├── VaultUnlocker.swift  # master password -> in-RAM session
        ├── CredentialIdentityUpdater.swift  # QuickType identity store
        └── MPConstants.swift
```

---

## Zero-knowledge model — what is stored where

| Data | Where | Protection |
|---|---|---|
| Master password | **nowhere, ever** | typed per unlock; used in RAM to derive the key |
| Derived AES key / RSA private key / vault keys | **RAM only** (`UnlockedSession`) | dropped on lock; process death ⇒ retype the master password |
| Server URL, email, device token (`mpd_…`) | shared **Keychain** group | `AfterFirstUnlockThisDeviceOnly`, never in backups of other devices |
| Vault cache (encrypted_private_key, name_encrypted, data_encrypted, wrapped vault keys) | **App Group file** `vault-cache.json` | ciphertext byte-for-byte as the server stores it; only ids/email are plaintext |
| QuickType identities (registrable domain + username + item id) | iOS **credential identity store** | OS-protected, local; **no passwords** — this metadata does leave app-level encryption, same as every iOS password manager |
| Biometric preference | App Group `UserDefaults` | not sensitive |

Consequences, stated honestly:

- **Face ID / Touch ID is a re-gate, not a key store.** The optional toggle
  only re-covers an *already unlocked* app after backgrounding. Nothing is
  stored that biometrics could decrypt, so after the process dies (reboot,
  memory pressure, force-quit) the master password must be typed again — in
  the app *and* in the AutoFill extension.
- **The extension can list nothing without an unlock.** It reads only the
  encrypted cache + keychain account; every fill prompts for the master
  password (`provideCredentialWithoutUserInteraction` always returns
  `userInteractionRequired`).
- The device token authorizes *API access to ciphertext* only; revoking it
  (web app → Settings → Devices) cuts the device off but was never able to
  decrypt anything by itself.

### Crypto compatibility (verified against `web/crypto.js`)

- **Key derivation** — PBKDF2-HMAC-SHA256, 600 000 iterations,
  salt = UTF-8(`"vault-internal:" + email`), 32-byte AES key.
  Production uses CommonCrypto's `CCKeyDerivationPBKDF` behind a
  `Pbkdf2Provider` protocol (a pure-Swift implementation backs Linux tests).
- **Blobs** — `base64( IV(12) ‖ ciphertext ‖ GCM tag(16) )`, which is exactly
  CryptoKit's `AES.GCM.SealedBox(combined:)` layout.
- **`encrypted_private_key`** decrypts to a **JWK JSON string** (RSA-4096
  with CRT parameters). `SecKeyCreateWithData` needs PKCS#1 DER, so
  `JwkToDer` converts base64url big-endian JWK integers into an ASN.1
  `RSAPrivateKey` — unit-tested byte-for-byte against Node's own
  `export({type:'pkcs1'})` of the same key.
- **Shared vaults** — `GET /api/vaults/:id/key` returns the vault key
  RSA-OAEP-encrypted (SHA-256 digest **and** MGF1, empty label =
  `.rsaEncryptionOAEPSHA256`); the OAEP plaintext is the *base64 string* of
  32 raw AES-key bytes. Personal vaults (`team_id == null`) use the derived
  key itself.
- **Pairing QR** — unpadded base64url of
  `{"v":1,"srv":origin,"email":…,"tok":"mpd_<uuid>_<b64url-secret>"}`.
- **TOTP** — RFC 6238, HMAC-SHA1, 30 s, 6 digits, permissive Base32.

---

## Building (requires a Mac)

There is deliberately **no hand-written `.pbxproj`** — the project is
generated from `project.yml`:

```bash
brew install xcodegen
cd ios
xcodegen generate          # -> MasPassword.xcodeproj (+ generated Info.plists/entitlements)
open MasPassword.xcodeproj
```

Build/run the `MasPassword` scheme (app + embedded `MasPasswordAutoFill`
extension). Command line:

```bash
xcodebuild -project MasPassword.xcodeproj -scheme MasPassword \
  -destination 'platform=iOS Simulator,name=iPhone 15' build
```

### Tests

```bash
cd ios/MasPasswordCore
swift test        # macOS: full suite incl. AES-GCM + RSA chain vectors
```

`swift test` also runs on **Linux** (pure-Swift portions; AES-GCM/RSA suites
skip themselves because CryptoKit/Security are Apple frameworks). The
vectors in `Tests/.../WebVectors.swift` were generated by running the real
`web/crypto.js` under Node's WebCrypto — the suite proves an item encrypted
by the web app decrypts here, the full RSA shared-vault chain unwraps, and
the JWK→DER conversion matches Node's DER exactly.

### Signing, App Group & Keychain sharing

1. In `project.yml`, set `DEVELOPMENT_TEAM` (or pick a team in Xcode →
   Signing & Capabilities after generating).
2. In the Apple Developer portal (Xcode's automatic signing does this for
   you with a paid account): both bundle ids —
   `com.maspassword.ios` and `com.maspassword.ios.autofill` — need
   **App Groups** (`group.com.maspassword.shared`), and the app id needs
   **AutoFill Credential Provider** implicitly via the extension point.
3. Keychain sharing uses access group
   `$(AppIdentifierPrefix)com.maspassword.shared`. Keep it as the **first**
   `keychain-access-groups` entry in both targets (the code stores items in
   the default group on purpose; see `MPConstants.swift`).
4. If you rename the group ids, change them in `project.yml` **and**
   `MPConstants.appGroupId` together.

---

## Linking a device (web QR flow)

1. Web vault → **Settings → Devices → Link device** → a QR is rendered
   (one-time device token inside; the payload carries **no key material**).
2. iOS app → **Link device** → scan the QR (or paste the code — same
   payload as text).
3. Enter the **master password once**. The app derives the key locally and
   verifies it by decrypting `encrypted_private_key` from
   `GET /api/auth/session` — a wrong password is a GCM tag failure, nothing
   more; the server cannot check passwords.
4. On success the app stores server/email/token in the shared keychain,
   writes the encrypted cache, decrypts in RAM, and publishes QuickType
   identities.

Re-linking is idempotent; revoke old device tokens from the web app.

## Enabling AutoFill on the phone

Settings → **Passwords → Password Options** → enable **AutoFill Passwords**
and tick **MasPassword** (iOS 17: *Settings → Passwords → Password Options →
Allow filling from*). Afterwards:

- QuickType shows `username — MasPassword` above the keyboard on matching
  sites/apps (identities are refreshed after every app unlock + sync).
- Tapping a suggestion (or picking MasPassword from the key icon) opens the
  extension, which asks for the master password, then fills.
- Matching is **fail-closed by registrable domain** (`Domains.swift`, the
  same eTLD+1 port the Chrome extension uses): `evil-google.com` never
  matches `google.com`; unparseable URLs match nothing.

## IAP caveat (mobile ingress)

If the server sits behind **Cloud IAP** (or any SSO proxy), browser cookies
make the web app work — but the iOS app talks JSON with a
`Bearer mpd_…` token and **cannot answer an interactive SSO redirect**.
`ApiClient` refuses to follow redirects and detects 30x/HTML responses,
surfacing a clear "server behind IAP" error instead of JSON parse noise.

Deployment options, in order of preference:

1. Expose `/api/**` on an ingress path that bypasses IAP for
   `Authorization: Bearer mpd_…` requests (the server itself authenticates
   them; middleware `DeviceTokenAuth` runs before the IAP fallback).
2. Run a second, non-IAP ingress (internal LB / VPN) for mobile clients.
3. Dev/self-hosted: no IAP — works out of the box.

## What was executed vs reviewed on this machine (no macOS here)

- **Executed** (Swift 6.1.2 toolchain, Ubuntu 24.04 aarch64):
  `swift test` on `MasPasswordCore` — 61 tests, 0 failures, 10 skipped
  (the skips are the CryptoKit AES-GCM open/seal and Security-framework RSA
  cases, which are Apple-only by design). Additionally the *full*
  600 000-iteration PBKDF2 derivation was executed in release mode
  (`MP_SLOW_TESTS=1`) against the web-generated key vector — byte-identical.
  The JWK→PKCS#1-DER conversion is verified byte-for-byte against Node's
  exporter, and every AES/RSA test vector in the suite was independently
  re-validated on this machine with Node 22 (see `WebVectors.swift` header).
- **Reviewed but not executed**: the app + extension targets (SwiftUI /
  AVFoundation / AuthenticationServices need Xcode + Apple SDKs), the
  `project.yml` generation, and the CryptoKit/Security code paths inside
  MasPasswordCore. All app-target sources were syntax-parsed with the Swift
  compiler; first build on a Mac may still surface SDK-level nits.
- The AES-GCM *framing* (`base64(iv‖ct‖tag)` split), key derivation, JWK
  conversion, TOTP, QR parsing, domain matching and all JSON parsing — i.e.
  every format decision — **did run here** against real web-generated data.
