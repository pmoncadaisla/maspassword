import Foundation

/// RFC 4648 base32 decoding, matching the permissive decoder in
/// web/crypto.js `base32Decode`: whitespace, '=' padding and '-' separators
/// are stripped, input is case-insensitive, and unknown characters are
/// skipped (not treated as errors).
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    private static let values: [Character: UInt8] = {
        var map: [Character: UInt8] = [:]
        for (i, c) in alphabet.enumerated() { map[c] = UInt8(i) }
        return map
    }()

    /// Decode a base32 string into raw bytes. Mirrors web/crypto.js:
    /// only complete 8-bit groups are emitted (trailing partial bits dropped).
    public static func decode(_ string: String) -> Data {
        var buffer: UInt32 = 0
        var bitsInBuffer: Int = 0
        var out = Data()
        for ch in string.uppercased() {
            guard let value = values[ch] else { continue } // skip spaces, '=', '-', junk
            buffer = (buffer << 5) | UInt32(value)
            bitsInBuffer += 5
            if bitsInBuffer >= 8 {
                bitsInBuffer -= 8
                out.append(UInt8((buffer >> UInt32(bitsInBuffer)) & 0xFF))
            }
        }
        return out
    }
}
