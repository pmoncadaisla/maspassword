import Foundation
import MasPasswordCore

/// Extension-side state machine:
///
///   notLinked          — no account in the shared keychain: open the app first
///   locked             — account + cache found, waiting for the master password
///   unlocked(list)     — decrypted; show matching + other items
///   configurationInfo  — invoked from Settings' "Set up" flow
///
/// The unlock is identical to the app's (VaultUnlocker) but the resulting
/// keys die with this extension process — nothing is written back anywhere.
@MainActor
final class AutoFillModel: ObservableObject {

    enum Phase: Equatable {
        case notLinked
        case locked
        case unlocked
        case configurationInfo
    }

    @Published private(set) var phase: Phase = .locked
    @Published private(set) var accountEmail = ""
    @Published private(set) var matchingItems: [DecryptedItem] = []
    @Published private(set) var otherLoginItems: [DecryptedItem] = []
    @Published var errorMessage: String?
    @Published var working = false

    /// Set by the view controller; called exactly once on success.
    var onProvide: ((_ username: String, _ password: String) -> Void)?
    var onCancel: (() -> Void)?

    private var request = AutoFillRequest()
    private var session: UnlockedSession?

    func begin(request: AutoFillRequest) {
        self.request = request
        guard let account = KeychainStore.loadAccount(), SharedCache.load() != nil else {
            phase = .notLinked
            return
        }
        accountEmail = account.email
        phase = .locked
    }

    func beginConfigurationInfo() {
        phase = .configurationInfo
    }

    func cancel() {
        onCancel?()
    }

    /// Master-password unlock against the cached ciphertext (fully offline).
    func unlock(masterPassword: String) {
        guard let cache = SharedCache.load() else {
            errorMessage = "No vault cache. Open the Sésamo app and unlock once."
            return
        }
        working = true
        errorMessage = nil
        // PBKDF2@600k runs ~a second on-device; do it off the main actor.
        Task.detached(priority: .userInitiated) { [request] in
            do {
                let session = try VaultUnlocker.unlock(cache: cache, masterPassword: masterPassword)
                await MainActor.run {
                    self.working = false
                    self.finishUnlock(session: session, request: request)
                }
            } catch {
                await MainActor.run {
                    self.working = false
                    if case VaultUnlocker.UnlockError.wrongMasterPassword = error {
                        self.errorMessage = "Wrong master password."
                    } else {
                        self.errorMessage = "\(error)"
                    }
                }
            }
        }
    }

    private func finishUnlock(session: UnlockedSession, request: AutoFillRequest) {
        self.session = session

        // QuickType fast path: a specific record was requested — serve it
        // immediately, no list needed.
        if let recordId = request.recordIdentifier,
           let item = session.allItems.first(where: { $0.id == recordId }) {
            provide(item)
            return
        }

        let logins = session.allItems.filter { $0.data.isLogin }
        matchingItems = logins.filter { item in
            request.serviceIdentifiers.contains { identifier in
                Domains.matches(serviceIdentifier: identifier.value,
                                kind: identifier.kind,
                                itemUrl: item.data.url)
            }
        }
        otherLoginItems = logins.filter { item in !matchingItems.contains(where: { $0.id == item.id }) }
        phase = .unlocked
    }

    func provide(_ item: DecryptedItem) {
        onProvide?(item.data.username, item.data.password)
    }

    func filteredOthers(query: String) -> [DecryptedItem] {
        guard !query.isEmpty else { return otherLoginItems }
        return otherLoginItems.filter { $0.data.matchesQuery(query) }
    }
}
