import Foundation

/// Typed views over the server's JSON responses. Kept in MasPasswordCore
/// (pure Foundation) so response parsing is unit-tested on any platform;
/// the app's ApiClient only moves bytes.
///
/// Response shapes come from the Go server:
///  - GET /api/auth/session      -> pkg/dto SessionInfoResponse
///  - GET /api/vaults            -> []models.Vault
///  - GET /api/vaults/:id/items  -> []models.Item
///  - GET /api/vaults/:id/key    -> {"encrypted_vault_key": ...}
///  - errors                     -> {"error":{"code":...,"message":...}}
public enum ApiModels {

    public struct SessionInfo: Equatable, Sendable {
        public let userId: String
        public let email: String
        public let displayName: String
        public let authMethod: String
        public let encryptionSetup: Bool
        /// AES-GCM blob containing the RSA private key JWK; empty if not set up.
        public let encryptedPrivateKey: String

        public init(userId: String, email: String, displayName: String, authMethod: String,
                    encryptionSetup: Bool, encryptedPrivateKey: String) {
            self.userId = userId
            self.email = email
            self.displayName = displayName
            self.authMethod = authMethod
            self.encryptionSetup = encryptionSetup
            self.encryptedPrivateKey = encryptedPrivateKey
        }
    }

    public struct VaultSummary: Equatable, Sendable, Identifiable {
        public let id: String
        /// AES-GCM blob; personal vaults decrypt with the derived key.
        public let nameEncrypted: String
        /// Non-nil => shared vault; its key comes from GET /api/vaults/:id/key.
        public let teamId: String?

        public var isShared: Bool { teamId != nil }

        public init(id: String, nameEncrypted: String, teamId: String?) {
            self.id = id
            self.nameEncrypted = nameEncrypted
            self.teamId = teamId
        }
    }

    public struct EncryptedItem: Equatable, Sendable, Identifiable {
        public let id: String
        public let vaultId: String
        public let dataEncrypted: String
        public let version: Int

        public init(id: String, vaultId: String, dataEncrypted: String, version: Int) {
            self.id = id
            self.vaultId = vaultId
            self.dataEncrypted = dataEncrypted
            self.version = version
        }
    }

    public struct ApiError: Equatable, Sendable {
        public let code: String
        public let message: String

        public init(code: String, message: String) {
            self.code = code
            self.message = message
        }
    }

    public enum ParseError: Error, Equatable {
        case notAnObject(String)
        case notAnArray(String)
    }

    // MARK: - parsers

    public static func parseSession(_ json: String) throws -> SessionInfo {
        guard let data = json.data(using: .utf8),
              let raw = try? JSONDecoder().decode(RawSession.self, from: data) else {
            throw ParseError.notAnObject("session")
        }
        return raw.value
    }

    public static func parseVaults(_ json: String) throws -> [VaultSummary] {
        try parseArray(json, of: RawVault.self, what: "vaults").map(\.value)
    }

    public static func parseItems(_ json: String) throws -> [EncryptedItem] {
        try parseArray(json, of: RawItemRow.self, what: "items").map(\.value)
    }

    public static func parseVaultKey(_ json: String) throws -> String {
        guard let data = json.data(using: .utf8),
              let raw = try? JSONDecoder().decode(RawVaultKey.self, from: data) else {
            throw ParseError.notAnObject("vault key")
        }
        return raw.encryptedVaultKey
    }

    /// Extract {"error":{code,message}} from an error body, or nil.
    public static func parseError(_ body: String?) -> ApiError? {
        guard let body, !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let data = body.data(using: .utf8),
              let raw = try? JSONDecoder().decode(RawErrorEnvelope.self, from: data),
              let inner = raw.error else { return nil }
        return ApiError(code: inner.code, message: inner.message)
    }

    // Go's c.JSON renders a nil slice as the literal "null" body.
    private static func parseArray<T: Decodable>(_ json: String, of type: T.Type, what: String) throws -> [T] {
        let trimmed = json.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed == "null" { return [] }
        guard let data = trimmed.data(using: .utf8),
              let array = try? JSONDecoder().decode(TolerantArray<T>.self, from: data) else {
            throw ParseError.notAnArray(what)
        }
        return array.elements
    }

    // MARK: - raw decodables (lenient)

    private struct RawSession: Decodable {
        let value: SessionInfo

        private enum CodingKeys: String, CodingKey {
            case userId = "user_id"
            case email
            case displayName = "display_name"
            case authMethod = "auth_method"
            case encryptionSetup = "encryption_setup"
            case encryptedPrivateKey = "encrypted_private_key"
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            value = SessionInfo(
                userId: c.lenientString(.userId),
                email: c.lenientString(.email),
                displayName: c.lenientString(.displayName),
                authMethod: c.lenientString(.authMethod),
                encryptionSetup: c.lenientBool(.encryptionSetup),
                encryptedPrivateKey: c.lenientString(.encryptedPrivateKey)
            )
        }
    }

    private struct RawVault: Decodable {
        let value: VaultSummary

        private enum CodingKeys: String, CodingKey {
            case id
            case nameEncrypted = "name_encrypted"
            case teamId = "team_id"
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            // team_id must distinguish null (personal) from a value (shared).
            let teamId = (try? c.decodeIfPresent(String.self, forKey: .teamId)) ?? nil
            value = VaultSummary(
                id: c.lenientString(.id),
                nameEncrypted: c.lenientString(.nameEncrypted),
                teamId: (teamId?.isEmpty ?? true) ? nil : teamId
            )
        }
    }

    private struct RawItemRow: Decodable {
        let value: EncryptedItem

        private enum CodingKeys: String, CodingKey {
            case id
            case vaultId = "vault_id"
            case dataEncrypted = "data_encrypted"
            case version
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            value = EncryptedItem(
                id: c.lenientString(.id),
                vaultId: c.lenientString(.vaultId),
                dataEncrypted: c.lenientString(.dataEncrypted),
                version: Int(c.lenientInt64(.version, default: 1))
            )
        }
    }

    private struct RawVaultKey: Decodable {
        let encryptedVaultKey: String

        private enum CodingKeys: String, CodingKey {
            case encryptedVaultKey = "encrypted_vault_key"
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            encryptedVaultKey = c.lenientString(.encryptedVaultKey)
        }
    }

    private struct RawErrorEnvelope: Decodable {
        let error: RawError?

        struct RawError: Decodable {
            let code: String
            let message: String

            private enum CodingKeys: String, CodingKey { case code, message }

            init(from decoder: Decoder) throws {
                let c = try decoder.container(keyedBy: CodingKeys.self)
                code = c.lenientString(.code)
                message = c.lenientString(.message)
            }
        }
    }
}
