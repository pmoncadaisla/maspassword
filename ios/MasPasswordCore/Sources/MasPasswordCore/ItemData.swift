import Foundation

/// A custom field stored inside the encrypted blob: {label, value, hidden}.
public struct CustomField: Equatable, Sendable, Decodable {
    public let label: String
    public let value: String
    public let hidden: Bool

    public init(label: String, value: String, hidden: Bool) {
        self.label = label
        self.value = value
        self.hidden = hidden
    }

    private enum CodingKeys: String, CodingKey { case label, value, hidden }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        label = c.lenientString(.label)
        value = c.lenientString(.value)
        hidden = c.lenientBool(.hidden)
    }
}

/// An attachment stored INSIDE the encrypted blob (see web/attachments.js):
/// {name, type, size, data} where data is base64 without any "data:" prefix.
public struct Attachment: Equatable, Sendable, Decodable {
    public let name: String
    public let type: String
    public let size: Int64
    public let data: String

    public init(name: String, type: String, size: Int64, data: String) {
        self.name = name
        self.type = type
        self.size = size
        self.data = data
    }

    private enum CodingKeys: String, CodingKey { case name, type, size, data }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let rawName = c.lenientString(.name)
        name = rawName.isEmpty ? "file" : rawName
        type = c.lenientString(.type)
        size = c.lenientInt64(.size)
        data = c.lenientString(.data)
    }
}

/// The decrypted item JSON, as written by `saveItem` in web/app.js. Read-only:
/// the iOS app never edits items, so unknown fields (card_*, id_*, icon,
/// pwChangedAt, ...) are preserved verbatim in `raw` instead of being modeled.
///
/// Known fields: type, title, username, password, url, notes, totp_secret,
/// tags, favorite, customFields, attachments. Types outside
/// {login, card, note, identity} normalize to "login", exactly like the web's
/// `itemType()`. Decoding is tolerant: null/missing/off-type fields never
/// fail the whole item (see Lenient.swift).
public struct ItemData: Equatable, Sendable {
    public let type: String
    public let title: String
    public let username: String
    public let password: String
    public let url: String
    public let notes: String
    public let totpSecret: String
    public let tags: [String]
    public let favorite: Bool
    public let customFields: [CustomField]
    public let attachments: [Attachment]
    /// The original decrypted JSON, untouched.
    public let raw: String

    public var isLogin: Bool { type == ItemData.typeLogin }

    public static let typeLogin = "login"
    public static let knownTypes: Set<String> = ["login", "card", "note", "identity"]

    public enum ItemError: Error, Equatable {
        case notJsonObject
    }

    /// Parse decrypted item JSON. Throws `ItemError.notJsonObject` when the
    /// plaintext is not a JSON object at all.
    public static func fromJson(_ json: String) throws -> ItemData {
        guard let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode(RawItem.self, from: data) else {
            throw ItemError.notJsonObject
        }
        return ItemData(decoded: decoded, raw: json)
    }

    private init(decoded d: RawItem, raw: String) {
        type = ItemData.knownTypes.contains(d.type) ? d.type : ItemData.typeLogin
        title = d.title
        username = d.username
        password = d.password
        url = d.url
        notes = d.notes
        totpSecret = d.totpSecret
        tags = d.tags
        favorite = d.favorite
        customFields = d.customFields
        attachments = d.attachments
        self.raw = raw
    }

    /// Case-insensitive search across title/username/url/notes/tags.
    public func matchesQuery(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if q.isEmpty { return true }
        if title.lowercased().contains(q) { return true }
        if username.lowercased().contains(q) { return true }
        if url.lowercased().contains(q) { return true }
        if notes.lowercased().contains(q) { return true }
        return tags.contains { $0.lowercased().contains(q) }
    }

    private struct RawItem: Decodable {
        let type: String
        let title: String
        let username: String
        let password: String
        let url: String
        let notes: String
        let totpSecret: String
        let tags: [String]
        let favorite: Bool
        let customFields: [CustomField]
        let attachments: [Attachment]

        private enum CodingKeys: String, CodingKey {
            case type, title, username, password, url, notes
            case totpSecret = "totp_secret"
            case tags, favorite, customFields, attachments
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            type = c.lenientString(.type)
            title = c.lenientString(.title)
            username = c.lenientString(.username)
            password = c.lenientString(.password)
            url = c.lenientString(.url)
            notes = c.lenientString(.notes)
            totpSecret = c.lenientString(.totpSecret)
            tags = c.lenientArray(LenientString.self, .tags)
                .map(\.value)
                .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            favorite = c.lenientBool(.favorite)
            customFields = c.lenientArray(CustomField.self, .customFields)
            attachments = c.lenientArray(Attachment.self, .attachments)
        }
    }
}
