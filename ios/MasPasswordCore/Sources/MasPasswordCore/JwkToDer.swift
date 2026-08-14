import Foundation

/// Converts a WebCrypto RSA private JWK (the JSON string that lives inside
/// `encrypted_private_key`) into a PKCS#1 `RSAPrivateKey` DER blob — the
/// format `SecKeyCreateWithData` requires for kSecAttrKeyTypeRSA private keys.
///
/// Why this exists: the web client stores the account keypair with
/// `exportKey('jwk', ...)`, so the decrypted plaintext is JWK JSON with
/// base64url big-endian parameters (n, e, d, p, q, dp, dq, qi). Apple's
/// Security framework cannot import JWK directly, so we build the ASN.1:
///
/// ```
/// RSAPrivateKey ::= SEQUENCE {
///   version         INTEGER (0),
///   modulus         INTEGER,  -- n
///   publicExponent  INTEGER,  -- e
///   privateExponent INTEGER,  -- d
///   prime1          INTEGER,  -- p
///   prime2          INTEGER,  -- q
///   exponent1       INTEGER,  -- dp (d mod (p-1))
///   exponent2       INTEGER,  -- dq (d mod (q-1))
///   coefficient     INTEGER   -- qi (q^-1 mod p)
/// }
/// ```
///
/// Pure Foundation — unit-tested on Linux against DER produced by Node's
/// `createPrivateKey({format:'jwk'}).export({type:'pkcs1',format:'der'})`
/// for the very JWK contained in the web-generated test vectors.
public enum JwkToDer {

    /// All eight RSA parameters are required: WebCrypto always exports the
    /// CRT form, and `SecKeyCreateWithData` needs the full private key anyway.
    /// (fail closed: no CRT-less fallback on iOS.)
    public static func rsaPrivateKeyDer(fromJwkJson jwkJson: String) throws -> Data {
        guard let jsonData = jwkJson.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: jsonData),
              let jwk = object as? [String: Any] else {
            throw CryptoError.invalidJwk("private key blob is not JWK JSON")
        }
        return try rsaPrivateKeyDer(fromJwk: jwk)
    }

    public static func rsaPrivateKeyDer(fromJwk jwk: [String: Any]) throws -> Data {
        let kty = jwk["kty"] as? String ?? ""
        guard kty == "RSA" else {
            throw CryptoError.invalidJwk("unsupported kty '\(kty)' (expected RSA)")
        }

        func param(_ name: String) throws -> Data {
            guard let b64u = jwk[name] as? String, !b64u.isEmpty else {
                throw CryptoError.invalidJwk("missing parameter '\(name)'")
            }
            guard let bytes = Base64URL.decode(b64u), !bytes.isEmpty else {
                throw CryptoError.invalidJwk("parameter '\(name)' is not base64url")
            }
            return bytes
        }

        var body = Data()
        body.append(Asn1.integer(magnitude: Data([0x00])))          // version 0
        body.append(Asn1.integer(magnitude: try param("n")))
        body.append(Asn1.integer(magnitude: try param("e")))
        body.append(Asn1.integer(magnitude: try param("d")))
        body.append(Asn1.integer(magnitude: try param("p")))
        body.append(Asn1.integer(magnitude: try param("q")))
        body.append(Asn1.integer(magnitude: try param("dp")))
        body.append(Asn1.integer(magnitude: try param("dq")))
        body.append(Asn1.integer(magnitude: try param("qi")))
        return Asn1.sequence(body)
    }
}

/// Minimal DER writer: only what RSAPrivateKey needs (INTEGER + SEQUENCE),
/// with definite lengths and minimal-form non-negative INTEGERs.
enum Asn1 {

    /// Encode a NON-NEGATIVE integer given as a big-endian magnitude
    /// (leading zeros tolerated, as base64url JWK params may carry them):
    /// strips redundant leading zeros, then prepends 0x00 when the top bit
    /// is set so the value stays positive in two's complement.
    static func integer(magnitude: Data) -> Data {
        var bytes = [UInt8](magnitude)
        while bytes.count > 1 && bytes[0] == 0x00 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = [0x00] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }
        var out = Data([0x02])
        out.append(length(bytes.count))
        out.append(contentsOf: bytes)
        return out
    }

    static func sequence(_ content: Data) -> Data {
        var out = Data([0x30])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    /// DER definite length: short form < 0x80, else 0x8N + N length bytes.
    static func length(_ count: Int) -> Data {
        precondition(count >= 0)
        if count < 0x80 { return Data([UInt8(count)]) }
        var value = count
        var lengthBytes: [UInt8] = []
        while value > 0 {
            lengthBytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(lengthBytes.count)] + lengthBytes)
    }
}
