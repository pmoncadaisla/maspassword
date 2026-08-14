import XCTest
@testable import MasPasswordCore

final class ApiModelsTests: XCTestCase {

    func testParseSession() throws {
        let json = #"""
        {"user_id":"u-1","email":"ana.garcía@example.com","display_name":"Ana",
         "auth_method":"device","encryption_setup":true,
         "encrypted_private_key":"BLOB=="}
        """#
        let session = try ApiModels.parseSession(json)
        XCTAssertEqual(session.userId, "u-1")
        XCTAssertEqual(session.email, "ana.garcía@example.com")
        XCTAssertEqual(session.displayName, "Ana")
        XCTAssertEqual(session.authMethod, "device")
        XCTAssertTrue(session.encryptionSetup)
        XCTAssertEqual(session.encryptedPrivateKey, "BLOB==")
    }

    func testParseSessionDefaults() throws {
        // encrypted_private_key is omitted when encryption is not set up
        // (Go omitempty) — must come back as "" and setup as false.
        let session = try ApiModels.parseSession(#"{"user_id":"u-1","email":"a@b.c"}"#)
        XCTAssertFalse(session.encryptionSetup)
        XCTAssertEqual(session.encryptedPrivateKey, "")
        XCTAssertEqual(session.displayName, "")

        XCTAssertThrowsError(try ApiModels.parseSession("not json"))
        XCTAssertThrowsError(try ApiModels.parseSession("[]"))
    }

    func testParseVaults() throws {
        let json = #"""
        [{"id":"v-1","name_encrypted":"AAA=","team_id":null,"owner_id":"u-1"},
         {"id":"v-2","name_encrypted":"BBB=","team_id":"t-9"},
         "not an object",
         {"id":"v-3","name_encrypted":"CCC="}]
        """#
        let vaults = try ApiModels.parseVaults(json)
        XCTAssertEqual(vaults.count, 3) // the string element is skipped
        XCTAssertEqual(vaults[0].id, "v-1")
        XCTAssertNil(vaults[0].teamId)
        XCTAssertFalse(vaults[0].isShared)
        XCTAssertEqual(vaults[1].teamId, "t-9")
        XCTAssertTrue(vaults[1].isShared)
        XCTAssertNil(vaults[2].teamId) // missing team_id == personal
    }

    func testParseVaultsNullAndEmptyBodies() throws {
        // Go's c.JSON renders a nil slice as the literal "null" body.
        XCTAssertEqual(try ApiModels.parseVaults("null"), [])
        XCTAssertEqual(try ApiModels.parseVaults("  null\n"), [])
        XCTAssertEqual(try ApiModels.parseVaults(""), [])
        XCTAssertEqual(try ApiModels.parseVaults("[]"), [])
        XCTAssertThrowsError(try ApiModels.parseVaults(#"{"not":"array"}"#))
    }

    func testParseItems() throws {
        let json = #"""
        [{"id":"i-1","vault_id":"v-1","data_encrypted":"XXX=","version":3},
         {"id":"i-2","vault_id":"v-1","data_encrypted":"YYY="}]
        """#
        let items = try ApiModels.parseItems(json)
        XCTAssertEqual(items.count, 2)
        XCTAssertEqual(items[0].version, 3)
        XCTAssertEqual(items[1].version, 1) // default
        XCTAssertEqual(items[1].dataEncrypted, "YYY=")
        XCTAssertEqual(try ApiModels.parseItems("null"), [])
    }

    func testParseVaultKey() throws {
        XCTAssertEqual(try ApiModels.parseVaultKey(#"{"encrypted_vault_key":"ZZZ="}"#), "ZZZ=")
        XCTAssertEqual(try ApiModels.parseVaultKey("{}"), "")
        XCTAssertThrowsError(try ApiModels.parseVaultKey("null"))
        XCTAssertThrowsError(try ApiModels.parseVaultKey("[]"))
    }

    func testParseError() {
        let err = ApiModels.parseError(#"{"error":{"code":"UNAUTHORIZED","message":"invalid device token"}}"#)
        XCTAssertEqual(err, ApiModels.ApiError(code: "UNAUTHORIZED", message: "invalid device token"))

        XCTAssertNil(ApiModels.parseError(nil))
        XCTAssertNil(ApiModels.parseError(""))
        XCTAssertNil(ApiModels.parseError("plain text"))
        XCTAssertNil(ApiModels.parseError("<html>IAP login</html>"))
        XCTAssertNil(ApiModels.parseError(#"{"something":"else"}"#))
    }
}
