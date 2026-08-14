import Foundation

/// Base64url (RFC 4648 §5) helpers. The device-link QR encodes its JSON
/// payload with base64url and no padding; JWK fields (n, e, d, ...) use the
/// same encoding.
public enum Base64URL {
    /// Decode a base64url string (padding optional). Returns nil on invalid input.
    public static func decode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Restore padding to a multiple of 4.
        let remainder = s.count % 4
        if remainder == 2 { s += "==" } else if remainder == 3 { s += "=" } else if remainder == 1 { return nil }
        return Data(base64Encoded: s)
    }

    /// Encode data as base64url without padding.
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
