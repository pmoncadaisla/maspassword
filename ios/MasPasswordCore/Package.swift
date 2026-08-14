// swift-tools-version:5.9
// MasPasswordCore — platform-independent logic for the MasPassword iOS app
// and its AutoFill extension: QR payload parsing, PBKDF2/AES-GCM/RSA-OAEP
// crypto compatible with web/crypto.js, TOTP (RFC 6238), domain matching,
// the REST API client and the shared keychain / autofill-cache stores.
//
// No third-party dependencies. `swift test` runs on macOS (full suite) and
// on Linux (AES-GCM/RSA cases skip themselves: CryptoKit / CommonCrypto /
// Security are Apple-SDK frameworks; everything else — derivation format,
// framing, JWK->DER, TOTP, parsing — executes everywhere).
import PackageDescription

let package = Package(
    name: "MasPasswordCore",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "MasPasswordCore", targets: ["MasPasswordCore"]),
    ],
    targets: [
        .target(
            name: "MasPasswordCore",
            path: "Sources/MasPasswordCore"
        ),
        .testTarget(
            name: "MasPasswordCoreTests",
            dependencies: ["MasPasswordCore"],
            path: "Tests/MasPasswordCoreTests"
        ),
    ]
)
