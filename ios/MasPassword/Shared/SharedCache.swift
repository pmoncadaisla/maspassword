import Foundation

/// The offline vault cache written by the app after every sync and read by
/// the AutoFill extension through the App Group container.
///
/// Zero-knowledge invariant: everything sensitive in this file is CIPHERTEXT
/// exactly as the server stores it (AES-GCM blobs, RSA-wrapped vault keys).
/// The only plaintext is structural: row ids, team ids and the account email
/// (needed as the PBKDF2 salt input; it is the login identity, not a secret).
/// Decrypting anything in here requires the master password.
struct VaultCache: Codable, Equatable {
    struct CachedVault: Codable, Equatable {
        var id: String
        /// AES-GCM blob; decrypts with the vault's own key.
        var nameEncrypted: String
        /// Non-nil => shared vault.
        var teamId: String?
        /// RSA-OAEP-wrapped vault key (GET /api/vaults/:id/key), shared vaults only.
        var encryptedVaultKey: String?
    }

    struct CachedItem: Codable, Equatable {
        var id: String
        var vaultId: String
        /// AES-GCM blob; decrypts with the owning vault's key.
        var dataEncrypted: String
        var version: Int
    }

    var fetchedAt: Date
    var email: String
    /// AES-GCM blob containing the account's RSA private key JWK.
    var encryptedPrivateKey: String
    var vaults: [CachedVault]
    var items: [CachedItem]
}

/// Reads/writes the cache file inside the App Group container.
enum SharedCache {

    static var fileName = "vault-cache.json"

    /// The App Group container, falling back to Application Support when the
    /// group is unavailable (e.g. running unit hosts without entitlements).
    /// In the real app + extension the group container is always used.
    static func containerURL() -> URL? {
        if let group = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: MPConstants.appGroupId) {
            return group
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
    }

    static func fileURL() -> URL? {
        containerURL()?.appendingPathComponent(fileName)
    }

    static func load() -> VaultCache? {
        guard let url = fileURL(), let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(VaultCache.self, from: data)
    }

    static func save(_ cache: VaultCache) throws {
        guard let url = fileURL() else {
            throw CocoaError(.fileNoSuchFile)
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(cache)
        // completeUntilFirstUserAuthentication matches the keychain class the
        // account record uses; the payload is ciphertext regardless.
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func clear() {
        guard let url = fileURL() else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
