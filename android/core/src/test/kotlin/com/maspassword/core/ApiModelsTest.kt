package com.maspassword.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Shapes mirror the Go server (pkg/dto, internal/models). */
class ApiModelsTest {

    @Test
    fun `parses GET api-auth-session (SessionInfoResponse)`() {
        val s = ApiModels.parseSession(
            """
            {"user_id":"u-1","email":"ana@example.com","display_name":"Ana",
             "auth_method":"device","encryption_setup":true,
             "encrypted_private_key":"${WebVectors.ENC_VAULT_NAME}",
             "srp_salt":"abc","token":"","is_admin":false}
            """.trimIndent(),
        )
        assertEquals("u-1", s.userId)
        assertEquals("ana@example.com", s.email)
        assertEquals("device", s.authMethod)
        assertTrue(s.encryptionSetup)
        assertEquals(WebVectors.ENC_VAULT_NAME, s.encryptedPrivateKey)
    }

    @Test
    fun `session without encryption setup has empty key (omitempty)`() {
        val s = ApiModels.parseSession("""{"user_id":"u","email":"e@x.com","encryption_setup":false}""")
        assertEquals("", s.encryptedPrivateKey)
        assertTrue(!s.encryptionSetup)
    }

    @Test
    fun `parses GET api-vaults - personal vs shared via team_id null`() {
        val vaults = ApiModels.parseVaults(
            """
            [{"id":"v1","owner_id":"u1","name_encrypted":"AAA","team_id":null,
              "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"},
             {"id":"v2","owner_id":"u1","name_encrypted":"BBB","team_id":"t9",
              "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}]
            """.trimIndent(),
        )
        assertEquals(2, vaults.size)
        assertEquals("v1", vaults[0].id)
        assertNull(vaults[0].teamId) // personal vault -> decrypt with derived key
        assertEquals("t9", vaults[1].teamId) // shared -> unwrap via /key
        assertEquals("BBB", vaults[1].nameEncrypted)
    }

    @Test
    fun `parses GET api-vaults-id-items`() {
        val items = ApiModels.parseItems(
            """
            [{"id":"i1","vault_id":"v1","data_encrypted":"CT","version":3,
              "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}]
            """.trimIndent(),
        )
        assertEquals(1, items.size)
        assertEquals("i1", items[0].id)
        assertEquals("v1", items[0].vaultId)
        assertEquals("CT", items[0].dataEncrypted)
        assertEquals(3, items[0].version)
    }

    @Test
    fun `go nil slices render as null body - treated as empty lists`() {
        assertTrue(ApiModels.parseVaults("null").isEmpty())
        assertTrue(ApiModels.parseItems("null").isEmpty())
        assertTrue(ApiModels.parseVaults("").isEmpty())
    }

    @Test
    fun `parses GET api-vaults-id-key (VaultKeyResponse)`() {
        assertEquals(
            WebVectors.ENC_VAULT_KEY,
            ApiModels.parseVaultKey("""{"encrypted_vault_key":"${WebVectors.ENC_VAULT_KEY}"}"""),
        )
    }

    @Test
    fun `parses the server error envelope`() {
        val e = ApiModels.parseError("""{"error":{"code":"UNAUTHORIZED","message":"device token revoked"}}""")
        assertEquals("UNAUTHORIZED", e!!.code)
        assertEquals("device token revoked", e.message)
        assertNull(ApiModels.parseError("""{"unrelated":true}"""))
        assertNull(ApiModels.parseError("<html>IAP login page</html>"))
        assertNull(ApiModels.parseError(null))
        assertNull(ApiModels.parseError(""))
    }
}
