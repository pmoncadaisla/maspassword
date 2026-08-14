import Foundation
#if canImport(Security)
import Security

/// RSA side of the shared-vault scheme, matching `web/crypto.js`
/// (verified against it and against `android/core .../RsaKeys.kt`):
///
///  - The account keypair is RSA-OAEP 4096 with SHA-256. The PRIVATE key is
///    stored server-side as a **JWK JSON string** (WebCrypto
///    `exportKey('jwk', ...)`) encrypted with the derived AES key via the
///    standard AES-GCM envelope. It is NOT PKCS#8: this module converts the
///    JWK to PKCS#1 DER (JwkToDer) and imports it with SecKeyCreateWithData.
///  - Shared-vault AES keys travel as RSA-OAEP ciphertexts of the vault
///    key's base64 STRING, so unwrapping = OAEP-decrypt -> UTF-8 string ->
///    base64 -> 32 raw key bytes.
///  - WebCrypto RSA-OAEP with `hash: SHA-256` uses SHA-256 for BOTH the OAEP
///    digest and MGF1, with an empty label — exactly Apple's
///    `.rsaEncryptionOAEPSHA256` algorithm.
public enum RsaKeys {

    /// Parse a WebCrypto RSA private JWK (JSON string) into a SecKey.
    public static func privateKey(fromJwkJson jwkJson: String) throws -> SecKey {
        let der = try JwkToDer.rsaPrivateKeyDer(fromJwkJson: jwkJson)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            throw CryptoError.rsaFailed(cfErrorMessage(error, fallback: "SecKeyCreateWithData failed"))
        }
        return key
    }

    /// Decrypt `encrypted_private_key` (from GET /api/auth/session) with the
    /// derived AES key and import the contained JWK. This doubles as the
    /// master-password verification: a wrong password fails the GCM tag check
    /// with `CryptoError.decryptionFailed`.
    public static func decryptPrivateKey(derivedKey: Data, encryptedPrivateKey: String) throws -> SecKey {
        try privateKey(fromJwkJson: VaultCrypto.decrypt(key: derivedKey, encoded: encryptedPrivateKey))
    }

    /// RSA-OAEP(SHA-256/MGF1-SHA-256) decrypt base64 ciphertext -> UTF-8 string.
    public static func rsaOaepDecryptToString(privateKey: SecKey, base64Ciphertext: String) throws -> String {
        guard let ciphertext = Data(base64Encoded: base64Ciphertext.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw CryptoError.invalidEncoding("RSA ciphertext is not valid base64")
        }
        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw CryptoError.rsaFailed("key does not support RSA-OAEP-SHA256 decryption")
        }
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(privateKey, algorithm, ciphertext as CFData, &error) else {
            throw CryptoError.rsaFailed(cfErrorMessage(error, fallback: "RSA-OAEP decryption failed"))
        }
        guard let text = String(data: plaintext as Data, encoding: .utf8) else {
            throw CryptoError.rsaFailed("RSA-OAEP plaintext is not UTF-8")
        }
        return text
    }

    /// Unwrap a shared vault's AES key: `encrypted_vault_key` from
    /// GET /api/vaults/:id/key -> OAEP decrypt -> base64 string -> 32 key bytes.
    public static func unwrapVaultKey(privateKey: SecKey, encryptedVaultKey: String) throws -> Data {
        try VaultCrypto.importVaultKey(
            base64: rsaOaepDecryptToString(privateKey: privateKey, base64Ciphertext: encryptedVaultKey)
        )
    }

    private static func cfErrorMessage(_ error: Unmanaged<CFError>?, fallback: String) -> String {
        guard let cfError = error?.takeRetainedValue() else { return fallback }
        return CFErrorCopyDescription(cfError) as String? ?? fallback
    }
}
#endif
