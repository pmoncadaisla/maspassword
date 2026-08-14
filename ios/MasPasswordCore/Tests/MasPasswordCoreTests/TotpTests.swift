import XCTest
@testable import MasPasswordCore

final class TotpTests: XCTestCase {

    /// RFC 6238 Appendix B vectors (HMAC-SHA1 mode, 8 digits, secret
    /// "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).
    func testRfc6238Sha1Vectors() throws {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        let cases: [(t: Int64, code: String)] = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ]
        for c in cases {
            XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: c.t, digits: 8).code, c.code, "t=\(c.t)")
        }
    }

    /// 6-digit codes for the demo secret used across the project, computed
    /// independently with Node's crypto (same algorithm as web/crypto.js).
    func testSixDigitKnownCodes() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: 59).code, "996554")
        XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: 1_111_111_109).code, "071271")
        XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: 1_723_620_000).code, "247594")
    }

    /// The permissive Base32 handling must not change the code: whitespace,
    /// '-' separators, '=' padding and lowercase are all tolerated.
    func testPermissiveSecretFormatting() throws {
        let canonical = try Totp.generate(secret: "JBSWY3DPEHPK3PXP", unixSeconds: 59)
        let sloppy = try Totp.generate(secret: "jbsw y3dp-ehpk 3pxp===", unixSeconds: 59)
        XCTAssertEqual(canonical, sloppy)
    }

    func testRemainingSeconds() throws {
        let secret = "JBSWY3DPEHPK3PXP"
        XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: 60).remainingSeconds, 30)
        XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: 61).remainingSeconds, 29)
        XCTAssertEqual(try Totp.generate(secret: secret, unixSeconds: 89).remainingSeconds, 1)
    }

    func testInvalidInputs() {
        XCTAssertThrowsError(try Totp.generate(secret: "", unixSeconds: 59)) {
            XCTAssertEqual($0 as? Totp.TotpError, .emptySecret)
        }
        // Only non-alphabet characters -> decodes to zero bytes.
        XCTAssertThrowsError(try Totp.generate(secret: "0189!", unixSeconds: 59)) {
            XCTAssertEqual($0 as? Totp.TotpError, .emptySecret)
        }
        XCTAssertThrowsError(try Totp.generate(secret: "JBSWY3DP", unixSeconds: 59, digits: 5)) {
            XCTAssertEqual($0 as? Totp.TotpError, .invalidDigits)
        }
        XCTAssertThrowsError(try Totp.generate(secret: "JBSWY3DP", unixSeconds: 59, periodSeconds: 0)) {
            XCTAssertEqual($0 as? Totp.TotpError, .invalidPeriod)
        }
    }

    // MARK: Base32 decoder (mirrors web/crypto.js base32Decode)

    func testBase32KnownBytes() {
        XCTAssertEqual(Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
                       Data("12345678901234567890".utf8))
        XCTAssertEqual(Base32.decode("JBSWY3DPEHPK3PXP").hexString, "48656c6c6f21deadbeef")
        // Trailing bits that don't fill a byte are dropped (web behavior):
        // "SXP" = 15 bits -> exactly one byte 0x95.
        XCTAssertEqual(Base32.decode("SXP").hexString, "95")
        // Unknown characters are silently skipped, not errors.
        XCTAssertEqual(Base32.decode("J!B@S#W1Y83D9P0EHPK3PXP"), Base32.decode("JBSWY3DPEHPK3PXP"))
        XCTAssertEqual(Base32.decode(""), Data())
    }
}
