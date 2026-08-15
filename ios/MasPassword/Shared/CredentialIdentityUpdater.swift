import Foundation
import AuthenticationServices

/// Publishes QuickType suggestions: one ASPasswordCredentialIdentity per
/// decrypted login item, keyed by the item's REGISTRABLE DOMAIN and carrying
/// the item id as recordIdentifier. iOS then surfaces "user@ · Sésamo"
/// above the keyboard on matching sites/apps; tapping it launches the
/// AutoFill extension with that record id (which still requires an unlock —
/// the identity store holds only domain + username + id, never passwords).
///
/// Honest data-exposure note (documented in ios/README.md too): domains and
/// usernames DO leave the app's own encryption when written to the system
/// identity store. That store is OS-encrypted and local, and it is exactly
/// how every iOS password manager integrates with QuickType — but it means
/// "usernames + sites" are readable by the OS once the user unlocks+syncs.
enum CredentialIdentityUpdater {

    /// Replace all published identities with the given rows. Call after each
    /// successful unlock+sync. No-op when the user hasn't enabled Sésamo
    /// in Settings > Passwords > Password Options.
    static func replaceAll(with rows: [(domain: String, username: String, recordId: String)]) async {
        let store = ASCredentialIdentityStore.shared
        let state = await store.state()
        guard state.isEnabled else { return }

        let identities = rows.map { row in
            ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: row.domain, type: .domain),
                user: row.username,
                recordIdentifier: row.recordId
            )
        }
        try? await store.replaceCredentialIdentities(with: identities)
    }

    /// Remove everything (unlink / wipe).
    static func removeAll() async {
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }
}
