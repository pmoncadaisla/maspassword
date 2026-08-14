package com.maspassword.app

import com.maspassword.core.ItemData
import java.security.interfaces.RSAPrivateKey
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKey

/**
 * In-memory session state. Holds every secret that must never touch disk:
 * the PBKDF2-derived AES key, the RSA private key, unwrapped shared-vault
 * keys, and the decrypted item cache. `lock()` (or process death) drops all
 * of them; recovering requires the master password again.
 */
class Session {

    /** One decrypted item, ready for list/search/detail/autofill. */
    data class DecryptedItem(
        val vaultId: String,
        val vaultName: String,
        val itemId: String,
        val version: Int,
        val data: ItemData,
    )

    data class Snapshot(
        val vaultNames: Map<String, String>,
        val items: List<DecryptedItem>,
        val loadedAtMillis: Long,
    )

    @Volatile var derivedKey: SecretKey? = null; private set
    @Volatile var privateKey: RSAPrivateKey? = null; private set
    /** Canonical account email from GET /api/auth/session (used for the salt). */
    @Volatile var accountEmail: String? = null; private set
    @Volatile var snapshot: Snapshot? = null

    /** Set after onStop when the biometric gate is enabled: re-check on return. */
    @Volatile var biometricGateArmed: Boolean = false

    private val vaultKeys = ConcurrentHashMap<String, SecretKey>()

    val isUnlocked: Boolean get() = derivedKey != null && privateKey != null

    fun unlock(derived: SecretKey, rsa: RSAPrivateKey, email: String) {
        derivedKey = derived
        privateKey = rsa
        accountEmail = email
    }

    /** Cache of unwrapped shared-vault keys (mirrors vaultKeyCache in web/app.js). */
    fun cachedVaultKey(vaultId: String): SecretKey? = vaultKeys[vaultId]

    fun cacheVaultKey(vaultId: String, key: SecretKey) {
        vaultKeys[vaultId] = key
    }

    fun findItem(itemId: String): DecryptedItem? =
        snapshot?.items?.firstOrNull { it.itemId == itemId }

    /** Drop every secret. Called from the Lock action and on unlink. */
    fun lock() {
        derivedKey = null
        privateKey = null
        accountEmail = null
        snapshot = null
        vaultKeys.clear()
        biometricGateArmed = false
    }
}
