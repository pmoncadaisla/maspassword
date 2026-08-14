package com.maspassword.core

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Typed views over the server's JSON responses. Kept in :core (pure JVM) so
 * response parsing is unit-tested; the :app module only moves bytes.
 *
 * Response shapes come from the Go server:
 *  - GET /api/auth/session  -> pkg/dto SessionInfoResponse
 *  - GET /api/vaults        -> []models.Vault
 *  - GET /api/vaults/:id/items -> []models.Item
 *  - GET /api/vaults/:id/key   -> pkg/dto VaultKeyResponse
 *  - errors                 -> {"error":{"code":...,"message":...}}
 */
object ApiModels {

    data class SessionInfo(
        val userId: String,
        val email: String,
        val displayName: String,
        val authMethod: String,
        val encryptionSetup: Boolean,
        /** AES-GCM blob containing the RSA private key JWK; empty if not set up. */
        val encryptedPrivateKey: String,
    )

    data class VaultSummary(
        val id: String,
        /** AES-GCM blob; personal vaults decrypt with the derived key. */
        val nameEncrypted: String,
        /** Non-null => shared vault; its key comes from GET /api/vaults/:id/key. */
        val teamId: String?,
    )

    data class EncryptedItem(
        val id: String,
        val vaultId: String,
        val dataEncrypted: String,
        val version: Int,
    )

    data class ApiError(val code: String, val message: String)

    fun parseSession(json: String): SessionInfo {
        val o = obj(json, "session")
        return SessionInfo(
            userId = optStr(o, "user_id"),
            email = optStr(o, "email"),
            displayName = optStr(o, "display_name"),
            authMethod = optStr(o, "auth_method"),
            encryptionSetup = o.optBoolean("encryption_setup", false),
            encryptedPrivateKey = optStr(o, "encrypted_private_key"),
        )
    }

    fun parseVaults(json: String): List<VaultSummary> {
        val arr = arr(json) ?: return emptyList()
        val out = mutableListOf<VaultSummary>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            out.add(
                VaultSummary(
                    id = optStr(o, "id"),
                    nameEncrypted = optStr(o, "name_encrypted"),
                    teamId = if (o.isNull("team_id")) null else o.optString("team_id"),
                ),
            )
        }
        return out
    }

    fun parseItems(json: String): List<EncryptedItem> {
        val arr = arr(json) ?: return emptyList()
        val out = mutableListOf<EncryptedItem>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            out.add(
                EncryptedItem(
                    id = optStr(o, "id"),
                    vaultId = optStr(o, "vault_id"),
                    dataEncrypted = optStr(o, "data_encrypted"),
                    version = o.optInt("version", 1),
                ),
            )
        }
        return out
    }

    fun parseVaultKey(json: String): String = optStr(obj(json, "vault key"), "encrypted_vault_key")

    /** Extract {"error":{code,message}} from an error body, or null. */
    fun parseError(body: String?): ApiError? {
        if (body.isNullOrBlank()) return null
        return try {
            val e = JSONObject(body).optJSONObject("error") ?: return null
            ApiError(optStr(e, "code"), optStr(e, "message"))
        } catch (ignored: JSONException) {
            null
        }
    }

    // Go's c.JSON renders a nil slice as the literal "null" body.
    private fun arr(json: String): JSONArray? {
        val t = json.trim()
        if (t.isEmpty() || t == "null") return null
        return try {
            JSONArray(t)
        } catch (e: JSONException) {
            throw IllegalArgumentException("expected a JSON array response", e)
        }
    }

    private fun obj(json: String, what: String): JSONObject = try {
        JSONObject(json)
    } catch (e: JSONException) {
        throw IllegalArgumentException("expected a JSON $what object", e)
    }

    // Android's optString would return "null" for JSON null — isNull first.
    private fun optStr(o: JSONObject, name: String): String =
        if (o.isNull(name)) "" else o.optString(name)
}
