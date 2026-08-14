import Foundation
import Security

/// The linked account, as stored in the SHARED keychain group after a
/// successful pairing. Contains the device token (a server credential) but
/// NEVER the master password or any derived/vault key — those exist only in
/// process memory while unlocked (zero-knowledge invariant).
struct LinkedAccount: Codable, Equatable {
    /// Server origin, e.g. "https://vault.example.com".
    var serverUrl: String
    /// Account email — also the PBKDF2 salt input ("vault-internal:"+email).
    var email: String
    /// Device API token "mpd_..." presented as a Bearer header.
    var token: String
    /// Display name reported by /api/auth/session at link time.
    var displayName: String
    var linkedAt: Date
}

/// Minimal keychain wrapper for the single LinkedAccount record.
///
/// Storage class is kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
/// available to the AutoFill extension after the first post-boot unlock,
/// never migrated to other devices via backup/restore.
enum KeychainStore {

    enum KeychainError: Error {
        case unexpectedStatus(OSStatus)
        case encoding
    }

    static func saveAccount(_ account: LinkedAccount) throws {
        guard let data = try? JSONEncoder().encode(account) else {
            throw KeychainError.encoding
        }
        // Replace-then-add keeps the code path simple and idempotent.
        SecItemDelete(baseQuery() as CFDictionary)

        var attributes = baseQuery()
        attributes[kSecValueData] = data
        attributes[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    static func loadAccount() -> LinkedAccount? {
        var query = baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(LinkedAccount.self, from: data)
    }

    static func deleteAccount() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private static func baseQuery() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: MPConstants.keychainService,
            kSecAttrAccount: MPConstants.keychainAccount,
            // No kSecAttrAccessGroup on purpose: the first entitlement group
            // (the shared one, per project.yml) is used, so both the app and
            // the extension resolve the same item without hardcoding the
            // team-id prefix. See MPConstants.
        ]
    }
}
