import Foundation
import SwiftUI
import LocalAuthentication
import MasPasswordCore

/// Central app model. Owns the phase machine
///
///   unlinked  ──link──▶  locked  ──unlock──▶  unlocked
///                          ▲                     │lock / background re-gate
///                          └─────────────────────┘
///
/// and the ONLY reference to the in-RAM UnlockedSession. The derived key is
/// never persisted anywhere; killing the process always returns to `locked`
/// and requires the master password again. The optional Face ID/Touch ID
/// gate only re-covers an ALREADY-UNLOCKED app after backgrounding — it can
/// never unlock a fresh process (there is nothing stored to unlock with).
@MainActor
final class AppState: ObservableObject {

    enum Phase: Equatable {
        case unlinked
        case locked
        case unlocked
    }

    @Published private(set) var phase: Phase = .unlinked
    @Published private(set) var account: LinkedAccount?
    @Published private(set) var session: UnlockedSession?
    @Published private(set) var syncing = false
    @Published var lastSyncError: String?
    /// True while the biometric curtain covers an unlocked app.
    @Published var biometricallyCovered = false

    private let defaults = UserDefaults(suiteName: MPConstants.appGroupId) ?? .standard

    var biometricGateEnabled: Bool {
        get { defaults.bool(forKey: MPConstants.biometricGateKey) }
        set { defaults.set(newValue, forKey: MPConstants.biometricGateKey); objectWillChange.send() }
    }

    init() {
        account = KeychainStore.loadAccount()
        phase = account == nil ? .unlinked : .locked
    }

    // MARK: - Linking

    /// Full pairing flow: verify the token against /api/auth/session, verify
    /// the master password by decrypting encrypted_private_key, sync the
    /// vaults, and only THEN persist the account to the shared keychain.
    func link(payload: LinkPayload, masterPassword: String) async throws {
        guard let client = ApiClient(serverUrl: payload.serverUrl, token: payload.token) else {
            throw ApiClientError.invalidResponse
        }

        // 1. The token must work and encryption must be set up.
        let sessionInfo = try await client.fetchSession()
        guard sessionInfo.encryptionSetup, !sessionInfo.encryptedPrivateKey.isEmpty else {
            throw VaultUnlocker.UnlockError.encryptionNotSetUp
        }

        // 2. Pull everything and build the encrypted cache.
        // Note: derivation uses the SESSION email (authoritative), which the
        // QR also carries for display.
        let cache = try await Self.buildCache(client: client,
                                              email: sessionInfo.email,
                                              encryptedPrivateKey: sessionInfo.encryptedPrivateKey)

        // 3. Verify the master password by unlocking (throws wrongMasterPassword).
        let unlocked = try VaultUnlocker.unlock(cache: cache, masterPassword: masterPassword)

        // 4. Persist: account -> shared keychain, ciphertext cache -> app group.
        let linkedAccount = LinkedAccount(serverUrl: payload.serverUrl,
                                          email: sessionInfo.email,
                                          token: payload.token,
                                          displayName: sessionInfo.displayName,
                                          linkedAt: Date())
        try KeychainStore.saveAccount(linkedAccount)
        try SharedCache.save(cache)

        account = linkedAccount
        session = unlocked
        phase = .unlocked
        await CredentialIdentityUpdater.replaceAll(with: unlocked.credentialIdentityRows())
    }

    // MARK: - Unlock / lock

    /// Offline-first unlock against the cached ciphertext; kicks off a
    /// background refresh afterwards.
    func unlock(masterPassword: String) async throws {
        guard let cache = SharedCache.load() else { throw VaultUnlocker.UnlockError.noCache }
        let unlocked = try VaultUnlocker.unlock(cache: cache, masterPassword: masterPassword)
        session = unlocked
        phase = .unlocked
        biometricallyCovered = false
        await CredentialIdentityUpdater.replaceAll(with: unlocked.credentialIdentityRows())
        Task { await self.sync() }
    }

    func lock() {
        session = nil
        biometricallyCovered = false
        if phase == .unlocked { phase = .locked }
    }

    /// Unlink: wipe keychain, cache, QuickType identities, and RAM keys.
    func unlink() async {
        KeychainStore.deleteAccount()
        SharedCache.clear()
        await CredentialIdentityUpdater.removeAll()
        session = nil
        account = nil
        phase = .unlinked
    }

    // MARK: - Sync

    /// Refresh the encrypted cache from the server and re-decrypt with the
    /// in-RAM keys. Safe to call only while unlocked.
    func sync() async {
        guard phase == .unlocked, let session, let account,
              let client = ApiClient(account: account) else { return }
        syncing = true
        defer { syncing = false }
        do {
            let info = try await client.fetchSession()
            // Never let a server hiccup blank out the key blob the next
            // unlock depends on.
            let keyBlob = info.encryptedPrivateKey.isEmpty
                ? (SharedCache.load()?.encryptedPrivateKey ?? "")
                : info.encryptedPrivateKey
            let cache = try await Self.buildCache(client: client,
                                                  email: info.email,
                                                  encryptedPrivateKey: keyBlob)
            try SharedCache.save(cache)
            session.applyCache(cache)
            lastSyncError = nil
            objectWillChange.send()
            await CredentialIdentityUpdater.replaceAll(with: session.credentialIdentityRows())
        } catch {
            lastSyncError = (error as? LocalizedError)?.errorDescription ?? "\(error)"
        }
    }

    private static func buildCache(client: ApiClient, email: String,
                                   encryptedPrivateKey: String) async throws -> VaultCache {
        let vaults = try await client.fetchVaults()

        var cachedVaults: [VaultCache.CachedVault] = []
        var cachedItems: [VaultCache.CachedItem] = []
        for vault in vaults {
            var wrappedKey: String?
            if vault.isShared {
                // Wrapped key travels once; decryption happens on-device only.
                wrappedKey = try await client.fetchVaultKey(vaultId: vault.id)
            }
            cachedVaults.append(VaultCache.CachedVault(id: vault.id,
                                                       nameEncrypted: vault.nameEncrypted,
                                                       teamId: vault.teamId,
                                                       encryptedVaultKey: wrappedKey))
            let items = try await client.fetchItems(vaultId: vault.id)
            cachedItems.append(contentsOf: items.map {
                VaultCache.CachedItem(id: $0.id, vaultId: $0.vaultId,
                                      dataEncrypted: $0.dataEncrypted, version: $0.version)
            })
        }
        return VaultCache(fetchedAt: Date(), email: email,
                          encryptedPrivateKey: encryptedPrivateKey,
                          vaults: cachedVaults, items: cachedItems)
    }

    // MARK: - Biometric re-gate

    /// Called when the scene returns to the foreground. If enabled and
    /// unlocked, cover the UI until Face ID / Touch ID / passcode succeeds.
    func handleScenePhase(_ scenePhase: ScenePhase) {
        guard phase == .unlocked, biometricGateEnabled else { return }
        switch scenePhase {
        case .background:
            biometricallyCovered = true
        case .active:
            if biometricallyCovered { Task { await self.evaluateBiometricGate() } }
        default:
            break
        }
    }

    private func evaluateBiometricGate() async {
        let context = LAContext()
        context.localizedFallbackTitle = "Enter device passcode"
        var error: NSError?
        // Device passcode fallback keeps the gate usable on devices without
        // biometrics; the master password is NEVER involved here.
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            // No passcode set at all: fall back to a hard lock.
            lock()
            return
        }
        do {
            let ok = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Unlock your Sésamo vaults")
            if ok { biometricallyCovered = false } else { lock() }
        } catch {
            lock() // cancel/failed -> require the master password again
        }
    }
}
