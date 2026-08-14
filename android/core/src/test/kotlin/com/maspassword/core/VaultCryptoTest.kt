package com.maspassword.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Verifies byte-for-byte compatibility with web/crypto.js using vectors
 * produced by the REAL web implementation (see WebVectors).
 */
class VaultCryptoTest {

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `deriveKey matches WebCrypto PBKDF2 output including non-ASCII and emoji`() {
        val key = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        assertEquals(WebVectors.DERIVED_KEY_HEX, hex(key.encoded))
        assertEquals("AES", key.algorithm)
        assertEquals(32, key.encoded.size)
    }

    @Test
    fun `decrypts an item encrypted by the web client with the derived key`() {
        val key = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        assertEquals(WebVectors.ITEM_JSON, VaultCrypto.decrypt(key, WebVectors.ENC_ITEM))
    }

    @Test
    fun `decrypts a personal vault name encrypted by the web client`() {
        val key = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        assertEquals("Personal", VaultCrypto.decrypt(key, WebVectors.ENC_VAULT_NAME))
    }

    @Test
    fun `encrypt output layout is base64 of iv12 then ciphertext then tag16`() {
        val key = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val plaintext = "layout-check"
        val combined = Base64.getDecoder().decode(VaultCrypto.encrypt(key, plaintext))
        // 12-byte IV + plaintext-sized ciphertext + 16-byte GCM tag.
        assertEquals(12 + plaintext.toByteArray().size + 16, combined.size)
        // And the web-produced vector has the same framing.
        val webCombined = Base64.getDecoder().decode(WebVectors.ENC_ITEM)
        val itemBytes = WebVectors.ITEM_JSON.toByteArray(Charsets.UTF_8)
        assertEquals(12 + itemBytes.size + 16, webCombined.size)
    }

    @Test
    fun `encrypt then decrypt round-trips unicode`() {
        val key = VaultCrypto.deriveKey("otra-clave", "user@example.com")
        val plaintext = "ñandú 🦤 \n\ttabs & \"quotes\""
        assertEquals(plaintext, VaultCrypto.decrypt(key, VaultCrypto.encrypt(key, plaintext)))
    }

    @Test
    fun `two encryptions of the same plaintext differ (random IV)`() {
        val key = VaultCrypto.deriveKey("otra-clave", "user@example.com")
        val a = VaultCrypto.encrypt(key, "same")
        val b = VaultCrypto.encrypt(key, "same")
        assertTrue(a != b)
    }

    @Test
    fun `wrong master password fails the GCM tag check`() {
        val wrong = VaultCrypto.deriveKey(WebVectors.PASSWORD + "x", WebVectors.EMAIL)
        assertThrows(CryptoException::class.java) {
            VaultCrypto.decrypt(wrong, WebVectors.ENC_ITEM)
        }
    }

    @Test
    fun `wrong email changes the salt and fails decryption`() {
        val wrong = VaultCrypto.deriveKey(WebVectors.PASSWORD, "other@example.com")
        assertThrows(CryptoException::class.java) {
            VaultCrypto.decrypt(wrong, WebVectors.ENC_ITEM)
        }
    }

    @Test
    fun `tampering with any ciphertext byte fails`() {
        val key = VaultCrypto.deriveKey(WebVectors.PASSWORD, WebVectors.EMAIL)
        val bytes = Base64.getDecoder().decode(WebVectors.ENC_ITEM)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte()
        val tampered = Base64.getEncoder().encodeToString(bytes)
        assertThrows(CryptoException::class.java) { VaultCrypto.decrypt(key, tampered) }
    }

    @Test
    fun `garbage and truncated inputs are rejected, not crashed on`() {
        val key = VaultCrypto.deriveKey("k", "e@x.com")
        assertThrows(CryptoException::class.java) { VaultCrypto.decrypt(key, "!!!not base64!!!") }
        assertThrows(CryptoException::class.java) { VaultCrypto.decrypt(key, "AAAA") } // < iv+tag
        assertThrows(CryptoException::class.java) { VaultCrypto.decrypt(key, "") }
    }

    @Test
    fun `importVaultKey decodes exactly 32 raw bytes`() {
        val key = VaultCrypto.importVaultKey(WebVectors.VAULT_KEY_B64)
        assertArrayEquals(Base64.getDecoder().decode(WebVectors.VAULT_KEY_B64), key.encoded)
        assertThrows(CryptoException::class.java) { VaultCrypto.importVaultKey("AAAA") }
        assertThrows(CryptoException::class.java) { VaultCrypto.importVaultKey("%%%") }
    }

    @Test
    fun `shared vault key decrypts an item encrypted by the web client`() {
        val vaultKey = VaultCrypto.importVaultKey(WebVectors.VAULT_KEY_B64)
        assertEquals(
            WebVectors.SHARED_ITEM_JSON,
            VaultCrypto.decrypt(vaultKey, WebVectors.ENC_SHARED_ITEM),
        )
    }
}
