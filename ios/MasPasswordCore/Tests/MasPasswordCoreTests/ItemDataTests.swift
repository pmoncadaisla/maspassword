import XCTest
@testable import MasPasswordCore

final class ItemDataTests: XCTestCase {

    /// Parse the EXACT plaintext the web client encrypts (WebVectors.itemJson,
    /// as built by web/app.js saveItem, including fields we don't model).
    func testParsesTheRealWebItemJson() throws {
        let item = try ItemData.fromJson(WebVectors.itemJson)
        XCTAssertEqual(item.type, "login")
        XCTAssertTrue(item.isLogin)
        XCTAssertEqual(item.title, "Ejemplo S.A.")
        XCTAssertEqual(item.username, "ana")
        XCTAssertEqual(item.password, "s3cret!ñ€")
        XCTAssertEqual(item.url, "https://app.example.co.uk/login")
        XCTAssertEqual(item.notes, "línea1\nlínea2")
        XCTAssertEqual(item.totpSecret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(item.tags, ["work", "ütf-8"])
        XCTAssertTrue(item.favorite)
        XCTAssertEqual(item.customFields, [CustomField(label: "PIN", value: "1234", hidden: true)])
        XCTAssertEqual(item.attachments,
                       [Attachment(name: "a.txt", type: "text/plain", size: 5, data: "aGVsbG8=")])
        // Unmodeled fields (icon, pwChangedAt) survive verbatim in raw.
        XCTAssertEqual(item.raw, WebVectors.itemJson)
        XCTAssertTrue(item.raw.contains("pwChangedAt"))
    }

    func testUnknownTypeNormalizesToLogin() throws {
        XCTAssertEqual(try ItemData.fromJson(#"{"type":"wifi"}"#).type, "login")
        XCTAssertEqual(try ItemData.fromJson(#"{"type":"card"}"#).type, "card")
        XCTAssertEqual(try ItemData.fromJson(#"{"type":"note"}"#).type, "note")
        XCTAssertEqual(try ItemData.fromJson(#"{"type":"identity"}"#).type, "identity")
        XCTAssertEqual(try ItemData.fromJson(#"{}"#).type, "login")
    }

    func testMinimalAndNullFields() throws {
        let item = try ItemData.fromJson(#"{"title":null,"username":null,"tags":null,"favorite":null}"#)
        XCTAssertEqual(item.title, "")
        XCTAssertEqual(item.username, "")
        XCTAssertEqual(item.tags, [])
        XCTAssertFalse(item.favorite)
        XCTAssertEqual(item.customFields, [])
        XCTAssertEqual(item.attachments, [])
    }

    func testTolerantFieldCoercion() throws {
        // Numbers coerce to strings (org.json optString semantics), null and
        // blank tags are dropped, broken array elements are skipped.
        let json = #"""
        {"title":42,"favorite":"true","tags":[null,"","a",42],
         "customFields":[{"label":"L","value":"V","hidden":true},"garbage",7],
         "attachments":[{"type":"text/plain","size":"5","data":"aGk="},null]}
        """#
        let item = try ItemData.fromJson(json)
        XCTAssertEqual(item.title, "42")
        XCTAssertTrue(item.favorite)
        XCTAssertEqual(item.tags, ["a", "42"])
        XCTAssertEqual(item.customFields, [CustomField(label: "L", value: "V", hidden: true)])
        XCTAssertEqual(item.attachments, [Attachment(name: "file", type: "text/plain", size: 5, data: "aGk=")])
    }

    func testRejectsNonObjects() {
        XCTAssertThrowsError(try ItemData.fromJson("not json")) {
            XCTAssertEqual($0 as? ItemData.ItemError, .notJsonObject)
        }
        XCTAssertThrowsError(try ItemData.fromJson("[1,2,3]")) {
            XCTAssertEqual($0 as? ItemData.ItemError, .notJsonObject)
        }
        XCTAssertThrowsError(try ItemData.fromJson("\"just a string\"")) {
            XCTAssertEqual($0 as? ItemData.ItemError, .notJsonObject)
        }
    }

    func testMatchesQuery() throws {
        let item = try ItemData.fromJson(WebVectors.itemJson)
        XCTAssertTrue(item.matchesQuery(""))
        XCTAssertTrue(item.matchesQuery("   "))
        XCTAssertTrue(item.matchesQuery("ejemplo"))       // title, case-insensitive
        XCTAssertTrue(item.matchesQuery("ANA"))           // username
        XCTAssertTrue(item.matchesQuery("example.co.uk")) // url
        XCTAssertTrue(item.matchesQuery("línea2"))        // notes
        XCTAssertTrue(item.matchesQuery("work"))          // tag
        XCTAssertFalse(item.matchesQuery("does-not-exist"))
        // The password is never searched.
        XCTAssertFalse(item.matchesQuery("s3cret"))
    }
}
