import XCTest
@testable import MasPasswordCore

/// End-to-end shared-vault chain against the web-generated vectors:
///
///   derive key -> decrypt encrypted_private_key -> JWK -> PKCS#1 DER ->
///   SecKey -> RSA-OAEP-SHA256 unwrap encrypted_vault_key -> vault key ->
///   decrypt a shared item.
///
/// Needs Security + CryptoKit, so it runs on Apple platforms only (Linux
/// hosts verify the JWK->DER step against Node's DER in JwkToDerTests and
/// skip the SecKey/OAEP half here).
final class RsaChainTests: XCTestCase {

    func testFullChainFromMasterPasswordToSharedItem() throws {
        #if canImport(Security) && canImport(CryptoKit)
        // 1. Master password -> derived key (600k iterations, CommonCrypto).
        let derivedKey = try VaultCrypto.deriveKey(masterPassword: WebVectors.password,
                                                   email: WebVectors.email)
        XCTAssertEqual(derivedKey.hexString, WebVectors.derivedKeyHex)

        // 2. encrypted_private_key -> RSA private SecKey (this step IS the
        //    master-password verification).
        let privateKey = try RsaKeys.decryptPrivateKey(derivedKey: derivedKey,
                                                       encryptedPrivateKey: WebVectors.encPrivateKey)

        // 3. encrypted_vault_key -> 32 raw AES bytes; must equal the vector.
        let vaultKey = try RsaKeys.unwrapVaultKey(privateKey: privateKey,
                                                  encryptedVaultKey: WebVectors.encVaultKey)
        XCTAssertEqual(vaultKey, Data(base64Encoded: WebVectors.vaultKeyB64)!)

        // 4. Shared item decrypts with the unwrapped key.
        XCTAssertEqual(try VaultCrypto.decrypt(key: vaultKey, encoded: WebVectors.encSharedItem),
                       WebVectors.sharedItemJson)
        #else
        throw XCTSkip("Needs Security + CryptoKit (Apple platforms)")
        #endif
    }

    func testWrongMasterPasswordFailsAtPrivateKeyDecrypt() throws {
        #if canImport(Security) && canImport(CryptoKit)
        let wrongKey = try VaultCrypto.deriveKey(masterPassword: WebVectors.password + "x",
                                                 email: WebVectors.email)
        XCTAssertThrowsError(try RsaKeys.decryptPrivateKey(derivedKey: wrongKey,
                                                           encryptedPrivateKey: WebVectors.encPrivateKey)) {
            XCTAssertEqual($0 as? CryptoError, .decryptionFailed)
        }
        #else
        throw XCTSkip("Needs Security + CryptoKit (Apple platforms)")
        #endif
    }

    func testDerImportsIntoSecurityFramework() throws {
        #if canImport(Security)
        // The Node-generated DER fixture must be importable as-is, proving
        // the format JwkToDer targets is the one SecKey expects.
        let key = try RsaKeys.privateKey(fromJwkJson: JwkFixtures.rsa4096JwkJson)
        let attrs = SecKeyCopyAttributes(key) as? [CFString: Any]
        XCTAssertEqual(attrs?[kSecAttrKeySizeInBits] as? Int, 4096)
        #else
        throw XCTSkip("Needs Security (Apple platforms)")
        #endif
    }
}
