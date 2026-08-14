package com.maspassword.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * End-to-end shared-vault chain against ciphertexts produced by the REAL web
 * client (web/crypto.js under Node WebCrypto):
 *
 *   master password ──PBKDF2──▶ derived key
 *   derived key + encrypted_private_key ──AES-GCM──▶ RSA private key (JWK)
 *   RSA key + encrypted_vault_key ──RSA-OAEP(SHA-256)──▶ vault AES key
 *   vault key + data_encrypted ──AES-GCM──▶ item JSON
 */
class RsaChainTest {

    @Test
    fun `full chain - password to shared item plaintext`() {
        val derived = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val rsa = RsaKeys.decryptPrivateKey(derived, WebVectors.ENC_PRIVATE_KEY)
        val vaultKey = RsaKeys.unwrapVaultKey(rsa, WebVectors.ENC_VAULT_KEY)
        assertEquals(
            WebVectors.SHARED_ITEM_JSON,
            VaultCrypto.decrypt(vaultKey, WebVectors.ENC_SHARED_ITEM),
        )
    }

    @Test
    fun `encrypted_private_key blob contains a JWK JSON, not PKCS8`() {
        val derived = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val json = VaultCrypto.decrypt(derived, WebVectors.ENC_PRIVATE_KEY)
        val jwk = JSONObject(json)
        assertEquals("RSA", jwk.getString("kty"))
        // WebCrypto private JWKs carry the full CRT parameter set.
        for (p in listOf("n", "e", "d", "p", "q", "dp", "dq", "qi")) {
            assertTrue("missing JWK param $p", jwk.has(p))
        }
    }

    @Test
    fun `web keypair is RSA-4096`() {
        val derived = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val rsa = RsaKeys.decryptPrivateKey(derived, WebVectors.ENC_PRIVATE_KEY)
        assertEquals(4096, rsa.modulus.bitLength())
    }

    @Test
    fun `oaep unwrap yields the exact base64 vault key string`() {
        val derived = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val rsa = RsaKeys.decryptPrivateKey(derived, WebVectors.ENC_PRIVATE_KEY)
        assertEquals(
            WebVectors.VAULT_KEY_B64,
            RsaKeys.rsaOaepDecryptToString(rsa, WebVectors.ENC_VAULT_KEY),
        )
    }

    @Test
    fun `jwk without CRT params still imports (n,d only)`() {
        val derived = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val full = JSONObject(VaultCrypto.decrypt(derived, WebVectors.ENC_PRIVATE_KEY))
        val minimal = JSONObject()
            .put("kty", "RSA")
            .put("n", full.getString("n"))
            .put("e", full.getString("e"))
            .put("d", full.getString("d"))
        val rsa = RsaKeys.privateKeyFromJwk(minimal.toString())
        // Without CRT hints decryption is slower but must still be correct.
        assertEquals(
            WebVectors.VAULT_KEY_B64,
            RsaKeys.rsaOaepDecryptToString(rsa, WebVectors.ENC_VAULT_KEY),
        )
    }

    @Test
    fun `malformed JWKs are rejected with CryptoException`() {
        assertThrows(CryptoException::class.java) { RsaKeys.privateKeyFromJwk("not json") }
        assertThrows(CryptoException::class.java) {
            RsaKeys.privateKeyFromJwk("""{"kty":"EC","crv":"P-256"}""")
        }
        assertThrows(CryptoException::class.java) {
            RsaKeys.privateKeyFromJwk("""{"kty":"RSA","n":"AQAB"}""") // missing d
        }
        assertThrows(CryptoException::class.java) {
            RsaKeys.privateKeyFromJwk("""{"kty":"RSA","n":"!!!","e":"AQAB","d":"AQAB"}""")
        }
    }

    @Test
    fun `tampered rsa ciphertext fails closed`() {
        val derived = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val rsa = RsaKeys.decryptPrivateKey(derived, WebVectors.ENC_PRIVATE_KEY)
        val bytes = java.util.Base64.getDecoder().decode(WebVectors.ENC_VAULT_KEY)
        bytes[0] = (bytes[0].toInt() xor 0x01).toByte()
        val tampered = java.util.Base64.getEncoder().encodeToString(bytes)
        assertThrows(CryptoException::class.java) { RsaKeys.rsaOaepDecryptToString(rsa, tampered) }
    }
}
