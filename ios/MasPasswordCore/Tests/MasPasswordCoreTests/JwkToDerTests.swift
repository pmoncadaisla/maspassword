import XCTest
@testable import MasPasswordCore

/// The JWK -> PKCS#1 DER conversion is compared BYTE-FOR-BYTE against DER
/// produced by Node's crypto for the same JWKs (see JwkFixtures). The 4096
/// fixture is the actual private key contained in the web-generated
/// `encrypted_private_key` vector, i.e. exactly what the app converts at
/// unlock time before handing it to SecKeyCreateWithData.
final class JwkToDerTests: XCTestCase {

    func testRsa4096FixtureMatchesNodeDer() throws {
        let der = try JwkToDer.rsaPrivateKeyDer(fromJwkJson: JwkFixtures.rsa4096JwkJson)
        let expected = Data(base64Encoded: JwkFixtures.rsa4096Pkcs1DerBase64)!
        XCTAssertEqual(der.count, expected.count)
        XCTAssertEqual(der, expected)
    }

    func testRsa2048FixtureMatchesNodeDer() throws {
        let der = try JwkToDer.rsaPrivateKeyDer(fromJwkJson: JwkFixtures.rsa2048JwkJson)
        XCTAssertEqual(der, Data(base64Encoded: JwkFixtures.rsa2048Pkcs1DerBase64)!)
    }

    func testRejectsNonRsaKty() {
        XCTAssertThrowsError(try JwkToDer.rsaPrivateKeyDer(fromJwkJson: #"{"kty":"EC","crv":"P-256"}"#)) {
            guard case CryptoError.invalidJwk(let why) = $0 else { return XCTFail("\($0)") }
            XCTAssertTrue(why.contains("EC"))
        }
    }

    func testRejectsMissingParameter() throws {
        // Remove "dq" from the valid 2048 fixture.
        var jwk = try JSONSerialization.jsonObject(
            with: Data(JwkFixtures.rsa2048JwkJson.utf8)) as! [String: Any]
        jwk.removeValue(forKey: "dq")
        XCTAssertThrowsError(try JwkToDer.rsaPrivateKeyDer(fromJwk: jwk)) {
            guard case CryptoError.invalidJwk(let why) = $0 else { return XCTFail("\($0)") }
            XCTAssertTrue(why.contains("dq"))
        }
    }

    func testRejectsBadBase64UrlParameter() throws {
        var jwk = try JSONSerialization.jsonObject(
            with: Data(JwkFixtures.rsa2048JwkJson.utf8)) as! [String: Any]
        jwk["n"] = "!!!" // not base64url
        XCTAssertThrowsError(try JwkToDer.rsaPrivateKeyDer(fromJwk: jwk)) {
            guard case CryptoError.invalidJwk(let why) = $0 else { return XCTFail("\($0)") }
            XCTAssertTrue(why.contains("n"))
        }
    }

    func testRejectsNonJson() {
        XCTAssertThrowsError(try JwkToDer.rsaPrivateKeyDer(fromJwkJson: "not json")) {
            guard case CryptoError.invalidJwk = $0 else { return XCTFail("\($0)") }
        }
    }

    // MARK: ASN.1 writer details

    func testAsn1IntegerMinimalEncoding() {
        // Plain small value.
        XCTAssertEqual(Asn1.integer(magnitude: Data([0x05])).hexString, "020105")
        // Zero stays a single byte.
        XCTAssertEqual(Asn1.integer(magnitude: Data([0x00])).hexString, "020100")
        XCTAssertEqual(Asn1.integer(magnitude: Data()).hexString, "020100")
        // Redundant leading zeros are stripped...
        XCTAssertEqual(Asn1.integer(magnitude: Data([0x00, 0x00, 0x05])).hexString, "020105")
        // ...but a 0x00 pad is added when the high bit is set (positive int).
        XCTAssertEqual(Asn1.integer(magnitude: Data([0x80])).hexString, "02020080")
        XCTAssertEqual(Asn1.integer(magnitude: Data([0x00, 0xff])).hexString, "020200ff")
    }

    func testAsn1LengthForms() {
        XCTAssertEqual(Asn1.length(0x7f).hexString, "7f")           // short form
        XCTAssertEqual(Asn1.length(0x80).hexString, "8180")         // 1 length byte
        XCTAssertEqual(Asn1.length(0x1234).hexString, "821234")     // 2 length bytes
        let seq = Asn1.sequence(Data(repeating: 0xab, count: 3))
        XCTAssertEqual(seq.hexString, "3003ababab")
    }
}
