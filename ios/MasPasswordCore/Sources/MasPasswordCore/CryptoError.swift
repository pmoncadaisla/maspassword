import Foundation

/// Every crypto failure in MasPasswordCore surfaces as one of these.
///
/// A wrong master password deliberately has no dedicated error: it shows up
/// as `.decryptionFailed` (an AES-GCM tag mismatch) when decrypting
/// `encrypted_private_key` or a personal item — exactly like the web client
/// and the Android app, and exactly because the server never learns anything
/// that could verify a password.
public enum CryptoError: Error, Equatable, CustomStringConvertible {
    /// Input that should have been base64/base64url was not decodable.
    case invalidEncoding(String)
    /// A combined AES-GCM blob shorter than IV(12) + tag(16).
    case ciphertextTooShort(Int)
    /// AES-GCM open failed: wrong key or corrupted/tampered data.
    case decryptionFailed
    /// AES-GCM seal failed (should not happen with valid inputs).
    case encryptionFailed
    /// A key had the wrong length (e.g. vault key not 32 bytes).
    case invalidKeyLength(Int)
    /// PBKDF2 provider reported a failure.
    case keyDerivationFailed(String)
    /// JWK parsing / conversion problems (missing params, wrong kty, ...).
    case invalidJwk(String)
    /// RSA import / OAEP decryption failed.
    case rsaFailed(String)
    /// The operation needs an Apple framework (CryptoKit / Security) that is
    /// unavailable on this platform (e.g. Linux test hosts).
    case platformUnsupported(String)
    /// Empty password/email or other precondition violations.
    case invalidArgument(String)

    public var description: String {
        switch self {
        case .invalidEncoding(let what): return "invalid encoding: \(what)"
        case .ciphertextTooShort(let n): return "ciphertext too short (\(n) bytes)"
        case .decryptionFailed: return "decryption failed (wrong key or corrupted data)"
        case .encryptionFailed: return "encryption failed"
        case .invalidKeyLength(let n): return "invalid key length (\(n) bytes)"
        case .keyDerivationFailed(let why): return "key derivation failed: \(why)"
        case .invalidJwk(let why): return "invalid JWK: \(why)"
        case .rsaFailed(let why): return "RSA operation failed: \(why)"
        case .platformUnsupported(let what): return "unsupported on this platform: \(what)"
        case .invalidArgument(let why): return "invalid argument: \(why)"
        }
    }
}
