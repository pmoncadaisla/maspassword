import Foundation

/// RFC 6238 TOTP, matching `generateTOTP` in web/crypto.js:
/// HMAC-SHA1, 30-second period, 6 digits, Base32 secret.
///
/// The Base32 decoder (see Base32.swift) mirrors the web one exactly:
/// whitespace, '=' padding and '-' separators are stripped, input is
/// uppercased, other non-alphabet characters are skipped, and trailing bits
/// that do not fill a byte are dropped.
///
/// HMAC-SHA1 uses the pure-Swift implementation (PureCrypto) so behavior is
/// identical on every test platform; it is pinned by the RFC 6238 vectors.
public enum Totp {

    public static let defaultPeriodSeconds = 30
    public static let defaultDigits = 6

    /// A generated code plus how many seconds it remains valid.
    public struct Code: Equatable, Sendable {
        public let code: String
        public let remainingSeconds: Int

        public init(code: String, remainingSeconds: Int) {
            self.code = code
            self.remainingSeconds = remainingSeconds
        }
    }

    public enum TotpError: Error, Equatable {
        case emptySecret
        case invalidPeriod
        case invalidDigits
    }

    /// Generate the code for `unixSeconds` (defaults to now). The counter is
    /// encoded as 8-byte big-endian; the web writes only the low 32 bits,
    /// which is identical for any timestamp before the year ~6000.
    public static func generate(
        secret: String,
        unixSeconds: Int64 = Int64(Date().timeIntervalSince1970),
        periodSeconds: Int = defaultPeriodSeconds,
        digits: Int = defaultDigits
    ) throws -> Code {
        guard periodSeconds > 0 else { throw TotpError.invalidPeriod }
        guard (6...8).contains(digits) else { throw TotpError.invalidDigits }
        let keyBytes = Base32.decode(secret)
        guard !keyBytes.isEmpty else { throw TotpError.emptySecret }

        // Clamp pathological pre-1970 clocks instead of trapping.
        let seconds = UInt64(max(0, unixSeconds))
        let counter = seconds / UInt64(periodSeconds)
        let remaining = periodSeconds - Int(seconds % UInt64(periodSeconds))

        var counterBytes = Data(capacity: 8)
        for shift in stride(from: 56, through: 0, by: -8) {
            counterBytes.append(UInt8((counter >> UInt64(shift)) & 0xff))
        }

        let hmac = [UInt8](PureCrypto.hmacSHA1(key: keyBytes, message: counterBytes))

        // RFC 4226 dynamic truncation.
        let offset = Int(hmac[hmac.count - 1] & 0x0f)
        let binary = (UInt32(hmac[offset] & 0x7f) << 24)
            | (UInt32(hmac[offset + 1]) << 16)
            | (UInt32(hmac[offset + 2]) << 8)
            | UInt32(hmac[offset + 3])

        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let code = String(format: "%0\(digits)d", binary % modulus)
        return Code(code: code, remainingSeconds: remaining)
    }
}
