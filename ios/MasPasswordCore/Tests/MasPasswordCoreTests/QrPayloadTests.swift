import XCTest
@testable import MasPasswordCore

final class QrPayloadTests: XCTestCase {

    private func payload(_ json: String) -> String {
        Base64URL.encode(Data(json.utf8))
    }

    func testParsesTheExactWebPayload() throws {
        let parsed = try QrPayload.parse(WebVectors.qrPayload)
        XCTAssertEqual(parsed.version, 1)
        XCTAssertEqual(parsed.serverUrl, "https://vault.example.com")
        XCTAssertEqual(parsed.email, "ana.garcía@example.com")
        XCTAssertEqual(parsed.token, WebVectors.deviceToken)
    }

    func testToleratesPaddingWhitespaceAndStandardAlphabet() throws {
        let canonical = try QrPayload.parse(WebVectors.qrPayload)

        // '=' padding restored
        var padded = WebVectors.qrPayload
        while padded.count % 4 != 0 { padded += "=" }
        XCTAssertEqual(try QrPayload.parse(padded), canonical)

        // whitespace / newlines sprinkled in (e.g. copy-paste from terminal)
        let spaced = WebVectors.qrPayload.enumerated()
            .map { $0.offset % 17 == 0 ? " \($0.element)" : String($0.element) }
            .joined() + "\n"
        XCTAssertEqual(try QrPayload.parse(spaced), canonical)

        // standard base64 alphabet (+/) re-encoding
        let standard = WebVectors.qrPayload
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        XCTAssertEqual(try QrPayload.parse(standard), canonical)
    }

    func testTrailingSlashOnServerIsStripped() throws {
        let raw = payload(#"{"v":1,"srv":"https://vault.example.com/","email":"a@b.c","tok":"\#(WebVectors.deviceToken)"}"#)
        XCTAssertEqual(try QrPayload.parse(raw).serverUrl, "https://vault.example.com")
    }

    func testRejectionCases() {
        func expect(_ raw: String, _ expected: QrPayload.ParseError, line: UInt = #line) {
            XCTAssertThrowsError(try QrPayload.parse(raw), line: line) {
                XCTAssertEqual($0 as? QrPayload.ParseError, expected, line: line)
            }
        }
        expect("", .empty)
        expect("   \n ", .empty)
        expect("!!!not-base64url!!!", .notBase64Url)
        expect(payload("this is not json"), .notJson)
        expect(payload(#"{"v":2,"srv":"https://x.example","email":"a@b.c","tok":"\#(WebVectors.deviceToken)"}"#),
               .unsupportedVersion(2))
        expect(payload(#"{"srv":"https://x.example","email":"a@b.c","tok":"\#(WebVectors.deviceToken)"}"#),
               .unsupportedVersion(-1))
        expect(payload(#"{"v":1,"srv":"ftp://x.example","email":"a@b.c","tok":"\#(WebVectors.deviceToken)"}"#),
               .missingServerUrl)
        expect(payload(#"{"v":1,"email":"a@b.c","tok":"\#(WebVectors.deviceToken)"}"#), .missingServerUrl)
        expect(payload(#"{"v":1,"srv":"https://x.example","tok":"\#(WebVectors.deviceToken)"}"#), .missingEmail)
        expect(payload(#"{"v":1,"srv":"https://x.example","email":"a@b.c","tok":"mpd_nope"}"#), .invalidToken)
        expect(payload(#"{"v":1,"srv":"https://x.example","email":"a@b.c"}"#), .invalidToken)
    }

    func testIsDeviceToken() {
        // The real format, secret containing '_' and '-' (split is positional).
        XCTAssertTrue(QrPayload.isDeviceToken(WebVectors.deviceToken))
        XCTAssertTrue(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_s"))

        XCTAssertFalse(QrPayload.isDeviceToken(""))
        XCTAssertFalse(QrPayload.isDeviceToken("jwt_something"))
        XCTAssertFalse(QrPayload.isDeviceToken("mpd_"))
        XCTAssertFalse(QrPayload.isDeviceToken("mpd_notauuid_secret"))
        // UUID with a non-hex char
        XCTAssertFalse(QrPayload.isDeviceToken("mpd_zc9c40b5-95a6-4be6-8d2f-14839e2a70cf_secret"))
        // Missing '_' separator at position 36
        XCTAssertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cfXsecret"))
        // Empty secret
        XCTAssertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_"))
        // Secret with non-base64url char
        XCTAssertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_se+cret"))
    }

    // MARK: Base64URL helper

    func testBase64UrlRoundtrip() {
        let data = Data([0xfb, 0xff, 0x00, 0x41, 0x7e])
        let encoded = Base64URL.encode(data)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(Base64URL.decode(encoded), data)
        XCTAssertNil(Base64URL.decode("a")) // remainder 1 is never valid
        XCTAssertEqual(Base64URL.decode("aGk"), Data("hi".utf8)) // unpadded
        XCTAssertEqual(Base64URL.decode("aGk="), Data("hi".utf8)) // padded ok
    }
}
