import Foundation

/// Tolerant-decoding building blocks shared by ItemData and ApiModels.
///
/// The web client writes item JSON, but older versions, imports and other
/// clients may leave fields null, missing, or with off-type values. Like the
/// Android client (org.json's optString semantics), decoding NEVER fails on
/// a weird field — it coerces or falls back to a default. Only a body that
/// is not a JSON object/array at all is an error.

/// A single JSON value coerced to String: strings pass through, numbers and
/// booleans are stringified, null/objects/arrays become "".
struct LenientString: Decodable {
    let value: String

    init(from decoder: Decoder) throws {
        let container = try? decoder.singleValueContainer()
        guard let container, !container.decodeNil() else {
            value = ""
            return
        }
        if let s = try? container.decode(String.self) {
            value = s
        } else if let i = try? container.decode(Int64.self) {
            value = String(i)
        } else if let d = try? container.decode(Double.self) {
            value = d == d.rounded() && abs(d) < 1e15
                ? String(Int64(d))
                : String(d)
        } else if let b = try? container.decode(Bool.self) {
            value = b ? "true" : "false"
        } else {
            value = ""
        }
    }
}

/// Decodes an array, silently SKIPPING elements that fail to decode
/// (mirrors Android's `arr.optJSONObject(i) ?: continue`).
struct TolerantArray<Element: Decodable>: Decodable {
    let elements: [Element]

    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        var out: [Element] = []
        while !container.isAtEnd {
            if let element = try? container.decode(Element.self) {
                out.append(element)
            } else if (try? container.decode(Discard.self)) == nil {
                break // cannot advance any further; stop instead of spinning
            }
        }
        elements = out
    }

    /// Decodes anything successfully without reading it — used to consume
    /// (and thereby skip) an element the real type could not decode.
    private struct Discard: Decodable {
        init(from decoder: Decoder) throws {}
    }
}

extension KeyedDecodingContainer {
    /// Missing / null / off-type -> "" (or the number/bool stringified).
    func lenientString(_ key: Key) -> String {
        (try? decodeIfPresent(LenientString.self, forKey: key))??.value ?? ""
    }

    /// Missing / null / off-type -> default. Accepts real bools and the
    /// strings "true"/"false".
    func lenientBool(_ key: Key, default defaultValue: Bool = false) -> Bool {
        if let b = try? decodeIfPresent(Bool.self, forKey: key) { return b }
        if let s = try? decodeIfPresent(String.self, forKey: key) {
            if s == "true" { return true }
            if s == "false" { return false }
        }
        return defaultValue
    }

    /// Missing / null / off-type -> default. Accepts integers, doubles and
    /// numeric strings.
    func lenientInt64(_ key: Key, default defaultValue: Int64 = 0) -> Int64 {
        if let i = try? decodeIfPresent(Int64.self, forKey: key) { return i }
        if let d = try? decodeIfPresent(Double.self, forKey: key) { return Int64(d) }
        if let s = try? decodeIfPresent(String.self, forKey: key), let i = Int64(s) { return i }
        return defaultValue
    }

    /// Missing / null / off-type / broken elements are all tolerated.
    func lenientArray<Element: Decodable>(_ type: Element.Type, _ key: Key) -> [Element] {
        (try? decodeIfPresent(TolerantArray<Element>.self, forKey: key))??.elements ?? []
    }
}
