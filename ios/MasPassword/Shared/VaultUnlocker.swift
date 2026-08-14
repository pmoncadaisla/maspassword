import Foundation
import Security
import MasPasswordCore

/// A vault whose key has been resolved, with its decrypted display name.
struct UnlockedVault: Identifiable, Equatable {
    let id: String
    let name: String
    let isShared: Bool
}

/// A decrypted item (metadata + parsed plaintext).
struct DecryptedItem: Identifiable, Equatable {
    let id: String
    let vaultId: String
    let data: ItemData
}

/// Everything derived from the master password. Lives ONLY in RAM: it is
/// never serialized, never written to keychain/disk, and dropped on lock.
/// Process death therefore always requires re-entering the master password.
final class UnlockedSession {
    let email: String
    /// PBKDF2-derived AES key — also the personal-vault key.
    private let derivedKey: Data
    /// RSA private key (unwraps shared-vault keys); nil when the account has
    /// no shared-vault crypto set up.
    private let privateKey: SecKey?
    /// Resolved AES key per vault id.
    private var vaultKeys: [String: Data] = [:]

    private(set) var vaults: [UnlockedVault] = []
    private(set) var itemsByVault: [String: [DecryptedItem]] = [:]

    init(email: String, derivedKey: Data, privateKey: SecKey?) {
        self.email = email
        self.derivedKey = derivedKey
        self.privateKey = privateKey
    }

    var allItems: [DecryptedItem] {
        itemsByVault.values.flatMap { $0 }
    }

    func items(inVault vaultId: String) -> [DecryptedItem] {
        itemsByVault[vaultId] ?? []
    }

    func vaultName(_ vaultId: String) -> String {
        vaults.first { $0.id == vaultId }?.name ?? ""
    }

    /// (Re-)decrypt the whole cache with the in-RAM keys. Called at unlock
    /// and again after every sync. Vaults whose key cannot be resolved or
    /// whose blobs fail to decrypt are dropped (fail closed) — a partial
    /// cache never produces garbage rows.
    func applyCache(_ cache: VaultCache) {
        var newVaults: [UnlockedVault] = []
        var newItems: [String: [DecryptedItem]] = [:]

        for vault in cache.vaults {
            guard let key = resolveKey(for: vault) else { continue }
            guard let name = try? VaultCrypto.decrypt(key: key, encoded: vault.nameEncrypted) else { continue }
            newVaults.append(UnlockedVault(id: vault.id, name: name, isShared: vault.teamId != nil))
        }

        for item in cache.items {
            guard let key = vaultKeys[item.vaultId] else { continue }
            guard let plaintext = try? VaultCrypto.decrypt(key: key, encoded: item.dataEncrypted),
                  let data = try? ItemData.fromJson(plaintext) else { continue }
            newItems[item.vaultId, default: []].append(
                DecryptedItem(id: item.id, vaultId: item.vaultId, data: data))
        }

        for vaultId in newItems.keys {
            newItems[vaultId]?.sort {
                $0.data.title.localizedCaseInsensitiveCompare($1.data.title) == .orderedAscending
            }
        }

        vaults = newVaults.sorted { (a, b) in
            if a.isShared != b.isShared { return !a.isShared } // personal first
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
        itemsByVault = newItems
    }

    private func resolveKey(for vault: VaultCache.CachedVault) -> Data? {
        if let cached = vaultKeys[vault.id] { return cached }
        let key: Data?
        if vault.teamId == nil {
            // Personal vault: the derived key itself (web behavior).
            key = derivedKey
        } else if let wrapped = vault.encryptedVaultKey, let privateKey {
            key = try? RsaKeys.unwrapVaultKey(privateKey: privateKey, encryptedVaultKey: wrapped)
        } else {
            key = nil
        }
        if let key { vaultKeys[vault.id] = key }
        return key
    }

    /// QuickType identity rows: (registrable domain, username, item id) for
    /// every decrypted LOGIN item that has a usable URL and a username.
    func credentialIdentityRows() -> [(domain: String, username: String, recordId: String)] {
        allItems.compactMap { item in
            guard item.data.isLogin, !item.data.username.isEmpty,
                  let domain = Domains.identityDomain(forItemUrl: item.data.url) else { return nil }
            return (domain, item.data.username, item.id)
        }
    }
}

enum VaultUnlocker {

    enum UnlockError: Error, Equatable {
        /// GCM tag mismatch opening encrypted_private_key = wrong password.
        case wrongMasterPassword
        /// The account has not completed encryption setup in the web app.
        case encryptionNotSetUp
        case noCache
    }

    /// Derive the key and verify the master password by decrypting
    /// `encrypted_private_key` — the ONLY password check that exists.
    /// Returns a fully decrypted in-RAM session.
    static func unlock(cache: VaultCache, masterPassword: String) throws -> UnlockedSession {
        guard !cache.encryptedPrivateKey.isEmpty else { throw UnlockError.encryptionNotSetUp }

        let derivedKey = try VaultCrypto.deriveKey(masterPassword: masterPassword, email: cache.email)

        let privateKey: SecKey
        do {
            privateKey = try RsaKeys.decryptPrivateKey(derivedKey: derivedKey,
                                                       encryptedPrivateKey: cache.encryptedPrivateKey)
        } catch CryptoError.decryptionFailed {
            throw UnlockError.wrongMasterPassword
        }

        let session = UnlockedSession(email: cache.email, derivedKey: derivedKey, privateKey: privateKey)
        session.applyCache(cache)
        return session
    }
}
