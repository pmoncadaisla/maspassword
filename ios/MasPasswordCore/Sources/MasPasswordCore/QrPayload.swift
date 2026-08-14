import Foundation

/// The parsed contents of a device-pairing QR code. Carries NO key material —
/// only the server origin, the account email (display) and the device token.
public struct LinkPayload: Equatable, Sendable {
    public let version: Int
    /// Server origin, e.g. "https://vault.example.com" (no trailing slash).
    public let serverUrl: String
    /// Account email — used for display; key derivation uses the session email.
    public let email: String
    /// Device API token, "mpd_<uuid>_<base64url secret>".
    public let token: String

    public init(version: Int, serverUrl: String, email: String, token: String) {
        self.version = version
        self.serverUrl = serverUrl
        self.email = email
        self.token = token
    }
}

/// Parser for the pairing payload produced by `renderDevicePairing` in
/// web/app.js: `base64url(JSON({"v":1,"srv":origin,"email":...,"tok":"mpd_..."}))`
/// with '=' padding stripped. Every failure throws `QrPayload.ParseError`
/// with a human-readable reason; nothing is ever guessed (fail closed).
public enum QrPayload {

    public static let supportedVersion = 1
    public static let tokenPrefix = "mpd_"

    public enum ParseError: Error, Equatable, CustomStringConvertible {
        case empty
        case notBase64Url
        case notJson
        case unsupportedVersion(Int)
        case missingServerUrl
        case missingEmail
        case invalidToken

        public var description: String {
            switch self {
            case .empty: return "empty pairing code"
            case .notBase64Url: return "not a pairing code (invalid base64url)"
            case .notJson: return "not a pairing code (invalid JSON)"
            case .unsupportedVersion(let v): return "unsupported pairing version '\(v)' (expected \(supportedVersion))"
            case .missingServerUrl: return "pairing code has no valid server URL"
            case .missingEmail: return "pairing code has no email"
            case .invalidToken: return "pairing code has no valid device token"
            }
        }
    }

    private struct RawPayload: Decodable {
        let v: Int?
        let srv: String?
        let email: String?
        let tok: String?
    }

    /// Parse a scanned or pasted pairing payload. Accepts the canonical
    /// unpadded base64url form; tolerates '=' padding, surrounding whitespace
    /// and standard-alphabet base64 (some share paths re-encode with +/).
    public static func parse(_ raw: String) throws -> LinkPayload {
        let compact = String(raw.unicodeScalars.filter { !CharacterSet.whitespacesAndNewlines.contains($0) })
        guard !compact.isEmpty else { throw ParseError.empty }

        let normalized = compact
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        var trimmed = normalized
        while trimmed.hasSuffix("=") { trimmed.removeLast() }

        guard let jsonData = Base64URL.decode(trimmed) else { throw ParseError.notBase64Url }
        guard let payload = try? JSONDecoder().decode(RawPayload.self, from: jsonData) else {
            throw ParseError.notJson
        }

        let version = payload.v ?? -1
        guard version == supportedVersion else { throw ParseError.unsupportedVersion(version) }

        var srv = (payload.srv ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        while srv.hasSuffix("/") { srv.removeLast() }
        guard srv.hasPrefix("https://") || srv.hasPrefix("http://") else {
            throw ParseError.missingServerUrl
        }

        let email = (payload.email ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty else { throw ParseError.missingEmail }

        let token = (payload.tok ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard isDeviceToken(token) else { throw ParseError.invalidToken }

        return LinkPayload(version: version, serverUrl: srv, email: email, token: token)
    }

    /// Shape check for a device token, mirroring `devicetoken.ParseID` on the
    /// server: "mpd_" + 36-char UUID + "_" + non-empty base64url secret. The
    /// split is positional because the secret may itself contain underscores.
    public static func isDeviceToken(_ raw: String) -> Bool {
        guard raw.hasPrefix(tokenPrefix) else { return false }
        let rest = raw.dropFirst(tokenPrefix.count)
        guard rest.count >= 38 else { return false }
        let chars = Array(rest)
        guard chars[36] == "_" else { return false }
        let uuid = String(chars[0..<36])
        let secret = String(chars[37...])
        return isUuid(uuid) && !secret.isEmpty && secret.allSatisfy(isBase64UrlChar)
    }

    private static func isUuid(_ s: String) -> Bool {
        let chars = Array(s.lowercased())
        guard chars.count == 36 else { return false }
        for (i, c) in chars.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if c != "-" { return false }
            } else if !c.isHexDigit {
                return false
            }
        }
        return true
    }

    private static func isBase64UrlChar(_ c: Character) -> Bool {
        c.isASCII && (c.isLetter || c.isNumber || c == "-" || c == "_")
    }
}
