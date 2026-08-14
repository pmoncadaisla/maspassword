import XCTest
@testable import MasPasswordCore

/// Pins the pure-Swift primitives to the standard vectors: FIPS 180 digests,
/// RFC 2202 / RFC 4231 HMAC, RFC-style PBKDF2-HMAC-SHA256 vectors.
final class PureCryptoTests: XCTestCase {

    // MARK: SHA-256 (FIPS 180-4 examples)

    func testSha256KnownVectors() {
        XCTAssertEqual(PureCrypto.sha256(Data("abc".utf8)).hexString,
                       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(PureCrypto.sha256(Data()).hexString,
                       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        // 56 bytes: exercises the two-block padding boundary.
        XCTAssertEqual(PureCrypto.sha256(Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)).hexString,
                       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    func testSha256AllLengthsUpToTwoBlocks() {
        // Padding correctness across every length 0..130 (crosses both block
        // boundaries); compared against nothing external, but must be stable
        // and 32 bytes — real value pinning comes from the fixed vectors above
        // and every PBKDF2/HMAC vector below.
        for n in 0...130 {
            XCTAssertEqual(PureCrypto.sha256(Data(repeating: 0x61, count: n)).count, 32)
        }
        // One spot value: 64 x 'a' (exactly one block of message).
        XCTAssertEqual(PureCrypto.sha256(Data(repeating: 0x61, count: 64)).hexString,
                       "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")
    }

    // MARK: SHA-1 (FIPS 180-4 examples)

    func testSha1KnownVectors() {
        XCTAssertEqual(PureCrypto.sha1(Data("abc".utf8)).hexString,
                       "a9993e364706816aba3e25717850c26c9cd0d89d")
        XCTAssertEqual(PureCrypto.sha1(Data()).hexString,
                       "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        XCTAssertEqual(PureCrypto.sha1(Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)).hexString,
                       "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
    }

    // MARK: HMAC (RFC 2202 / RFC 4231)

    func testHmacSha1Rfc2202() {
        XCTAssertEqual(
            PureCrypto.hmacSHA1(key: Data(repeating: 0x0b, count: 20), message: Data("Hi There".utf8)).hexString,
            "b617318655057264e28bc0b6fb378c8ef146be00")
        XCTAssertEqual(
            PureCrypto.hmacSHA1(key: Data("Jefe".utf8), message: Data("what do ya want for nothing?".utf8)).hexString,
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
    }

    func testHmacSha256Rfc4231() {
        XCTAssertEqual(
            PureCrypto.hmacSHA256(key: Data(repeating: 0x0b, count: 20), message: Data("Hi There".utf8)).hexString,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        XCTAssertEqual(
            PureCrypto.hmacSHA256(key: Data("Jefe".utf8), message: Data("what do ya want for nothing?".utf8)).hexString,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        // Key longer than the block size must be hashed first (RFC 4231 TC6).
        XCTAssertEqual(
            PureCrypto.hmacSHA256(key: Data(repeating: 0xaa, count: 131),
                                  message: Data("Test Using Larger Than Block-Size Key - Hash Key First".utf8)).hexString,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    }

    // MARK: PBKDF2-HMAC-SHA256

    func testPbkdf2Sha256KnownVectors() {
        let cases: [(password: String, salt: String, iterations: Int, keyLength: Int, hex: String)] = [
            ("password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            ("password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            ("password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
            // keyLength > hash size: exercises the multi-block T_i loop.
            ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
             "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"),
        ]
        for c in cases {
            XCTAssertEqual(
                PureCrypto.pbkdf2SHA256(password: Data(c.password.utf8), salt: Data(c.salt.utf8),
                                        iterations: c.iterations, keyLength: c.keyLength).hexString,
                c.hex, "PBKDF2(\(c.password), \(c.salt), \(c.iterations), \(c.keyLength))")
        }
    }

    /// The real MasPassword derivation format ("vault-internal:"+email salt,
    /// UTF-8 password with emoji) at 1 000 iterations, computed with Node —
    /// verifies the exact byte inputs cheaply on every platform.
    func testPbkdf2MasPasswordFormat1000Iterations() {
        let derived = PureCrypto.pbkdf2SHA256(
            password: Data(WebVectors.password.utf8),
            salt: Data((VaultCrypto.saltPrefix + WebVectors.email).utf8),
            iterations: 1000, keyLength: 32)
        XCTAssertEqual(derived.hexString, WebVectors.derivedKey1000Hex)
    }

    #if canImport(CommonCrypto)
    /// CommonCrypto and the pure-Swift implementation must agree bit-for-bit.
    func testCommonCryptoAndPureSwiftAgree() throws {
        let password = Data(WebVectors.password.utf8)
        let salt = Data((VaultCrypto.saltPrefix + WebVectors.email).utf8)
        let cc = try CommonCryptoPbkdf2().deriveKey(password: password, salt: salt, iterations: 1000, keyLength: 32)
        let pure = try PureSwiftPbkdf2().deriveKey(password: password, salt: salt, iterations: 1000, keyLength: 32)
        XCTAssertEqual(cc.hexString, pure.hexString)
    }
    #endif
}
