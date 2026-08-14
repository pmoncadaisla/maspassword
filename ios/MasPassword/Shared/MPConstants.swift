import Foundation

/// Identifiers shared between the app and the AutoFill extension.
///
/// IMPORTANT (signing): both `appGroupId` and the keychain access group
/// `com.maspassword.shared` must exist in BOTH targets' entitlements — see
/// ios/project.yml, which declares them, and ios/README.md for the developer
/// portal setup. The keychain code deliberately does NOT pass
/// kSecAttrAccessGroup: items land in the FIRST keychain-access-group of the
/// entitlements, which project.yml keeps as the shared group for both
/// targets. Do not reorder the entitlement arrays.
enum MPConstants {
    /// App Group container shared by app + extension (encrypted cache lives here).
    static let appGroupId = "group.com.maspassword.shared"

    /// Keychain service name for the linked-account record.
    static let keychainService = "com.maspassword.account"

    /// Keychain account name for the single linked-account record.
    static let keychainAccount = "linked-account"

    /// UserDefaults(suiteName: appGroupId) keys.
    static let biometricGateKey = "mp.biometricGateEnabled"

    /// Clipboard auto-expiration for copied secrets, in seconds.
    static let clipboardTtlSeconds: TimeInterval = 60
}
