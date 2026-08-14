package com.maspassword.app.net

import com.maspassword.app.SecureStore
import com.maspassword.app.Session
import com.maspassword.core.ApiModels
import com.maspassword.core.CryptoException
import com.maspassword.core.Domains
import com.maspassword.core.ItemData
import com.maspassword.core.RsaKeys
import com.maspassword.core.VaultCrypto
import javax.crypto.SecretKey

/** Master password did not decrypt the account's private key. */
class WrongPasswordException : Exception("wrong master password")

/** The account has never opened the web vault, so no keys exist yet. */
class EncryptionNotSetUpException :
    Exception("this account has no encryption keys yet — sign in to the web vault once first")

/**
 * All server orchestration. Every method here is BLOCKING and must be called
 * through [com.maspassword.app.Bg]. The decrypt-everything approach mirrors
 * the web client (web/app.js): ciphertexts come down, plaintext never goes up
 * — this client is read-only and cannot even write.
 */
class VaultRepository(private val store: SecureStore, val session: Session) {

    private fun client(): ApiClient {
        val server = store.serverUrl ?: throw IllegalStateException("device not linked")
        val token = store.deviceToken ?: throw IllegalStateException("device not linked")
        return ApiClient(server, token)
    }

    /**
     * Link flow (called with the values scanned from the QR, BEFORE anything
     * is persisted): fetch the session with the device token, derive the key
     * from the master password + the server's canonical account email, and
     * prove the password by decrypting `encrypted_private_key`. Only on
     * success is the link written to the Keystore-encrypted store.
     */
    fun linkAndUnlock(serverUrl: String, deviceToken: String, masterPassword: String) {
        val api = ApiClient(serverUrl, deviceToken)
        unlockWith(api, masterPassword)
        store.saveLink(serverUrl, session.accountEmail ?: "", deviceToken)
    }

    /** Unlock an already-linked device (normal app open after process death). */
    fun unlock(masterPassword: String) {
        unlockWith(client(), masterPassword)
    }

    private fun unlockWith(api: ApiClient, masterPassword: String) {
        val info = ApiModels.parseSession(api.get("/api/auth/session"))
        if (!info.encryptionSetup || info.encryptedPrivateKey.isEmpty()) {
            throw EncryptionNotSetUpException()
        }
        // The salt email is the account's canonical email (what the web client
        // used when it encrypted the private key), NOT whatever was typed/scanned.
        val derived = VaultCrypto.deriveKey(masterPassword, info.email)
        val rsa = try {
            RsaKeys.decryptPrivateKey(derived, info.encryptedPrivateKey)
        } catch (e: CryptoException) {
            throw WrongPasswordException()
        }
        session.unlock(derived, rsa, info.email)
    }

    /**
     * Vault key selection, mirroring `getVaultDecryptionKey` in web/app.js:
     * personal vaults (team_id == null) use the DERIVED KEY ITSELF; shared
     * vaults unwrap their AES key from GET /api/vaults/:id/key with the RSA
     * private key (RSA-OAEP SHA-256), cached per vault.
     */
    private fun vaultKey(api: ApiClient, vault: ApiModels.VaultSummary): SecretKey {
        val derived = session.derivedKey ?: throw IllegalStateException("locked")
        if (vault.teamId == null) return derived
        session.cachedVaultKey(vault.id)?.let { return it }
        val rsa = session.privateKey ?: throw IllegalStateException("locked")
        val encVaultKey = ApiModels.parseVaultKey(api.get("/api/vaults/${vault.id}/key"))
        val key = RsaKeys.unwrapVaultKey(rsa, encVaultKey)
        session.cacheVaultKey(vault.id, key)
        return key
    }

    /**
     * Fetch and decrypt everything: GET /api/vaults, then per vault its key
     * (if shared) and GET /api/vaults/:id/items. Items that fail to decrypt
     * or parse are skipped, exactly like the web and the extension do.
     */
    fun loadAll(forceRefresh: Boolean = false): Session.Snapshot {
        session.snapshot?.let {
            if (!forceRefresh && System.currentTimeMillis() - it.loadedAtMillis < CACHE_TTL_MS) return it
        }
        val api = client()
        val vaults = ApiModels.parseVaults(api.get("/api/vaults"))

        val names = LinkedHashMap<String, String>()
        val items = ArrayList<Session.DecryptedItem>()
        for (vault in vaults) {
            val key = try {
                vaultKey(api, vault)
            } catch (e: CryptoException) {
                continue // cannot unwrap this vault's key: skip it, keep the rest
            }
            val name = try {
                VaultCrypto.decrypt(key, vault.nameEncrypted)
            } catch (e: CryptoException) {
                "(vault)"
            }
            names[vault.id] = name

            for (item in ApiModels.parseItems(api.get("/api/vaults/${vault.id}/items"))) {
                try {
                    val data = ItemData.fromJson(VaultCrypto.decrypt(key, item.dataEncrypted))
                    items.add(Session.DecryptedItem(vault.id, name, item.id, item.version, data))
                } catch (ignored: Exception) {
                    // Undecryptable/corrupt item: skip (mirrors web catch {}).
                }
            }
        }
        // Favorites first, then title — same ordering as the web list.
        items.sortWith(
            compareByDescending<Session.DecryptedItem> { it.data.favorite }
                .thenBy { it.data.title.lowercase() },
        )
        val snapshot = Session.Snapshot(names, items, System.currentTimeMillis())
        session.snapshot = snapshot
        return snapshot
    }

    /**
     * Fail-closed autofill matching (pure logic in :core Domains): only login
     * items whose saved URL shares the page's registrable domain. No web
     * domain (native app) -> empty list, always.
     */
    fun matchesForDomain(webDomain: String?): List<Session.DecryptedItem> {
        val snap = session.snapshot ?: return emptyList()
        if (webDomain.isNullOrBlank()) return emptyList()
        return snap.items.filter { it.data.isLogin && Domains.autofillMatch(webDomain, it.data.url) }
    }

    private companion object {
        const val CACHE_TTL_MS = 60_000L
    }
}
