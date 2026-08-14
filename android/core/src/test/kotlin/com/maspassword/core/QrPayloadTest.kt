package com.maspassword.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class QrPayloadTest {

    @Test
    fun `parses the exact payload web renderDevicePairing emits`() {
        val p = QrPayload.parse(WebVectors.QR_PAYLOAD)
        assertEquals(1, p.version)
        assertEquals("https://vault.example.com", p.serverUrl)
        assertEquals(WebVectors.EMAIL, p.email) // non-ASCII email survives UTF-8/base64url
        assertEquals(WebVectors.DEVICE_TOKEN, p.token)
    }

    @Test
    fun `tolerates padding whitespace and standard base64 alphabet on paste`() {
        val padded = WebVectors.QR_PAYLOAD + "=".repeat((4 - WebVectors.QR_PAYLOAD.length % 4) % 4)
        assertEquals(QrPayload.parse(WebVectors.QR_PAYLOAD), QrPayload.parse(" $padded \n"))

        // Same JSON re-encoded with the standard '+/' alphabet still parses.
        val json = String(Base64.getUrlDecoder().decode(WebVectors.QR_PAYLOAD), Charsets.UTF_8)
        val standard = Base64.getEncoder().encodeToString(json.toByteArray(Charsets.UTF_8))
        assertEquals(QrPayload.parse(WebVectors.QR_PAYLOAD), QrPayload.parse(standard))
    }

    @Test
    fun `server url loses its trailing slash`() {
        val json = """{"v":1,"srv":"https://x.example.com/","email":"a@b.c","tok":"${WebVectors.DEVICE_TOKEN}"}"""
        val encoded = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(json.toByteArray(Charsets.UTF_8))
        assertEquals("https://x.example.com", QrPayload.parse(encoded).serverUrl)
    }

    private fun encode(json: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray(Charsets.UTF_8))

    @Test
    fun `rejects wrong version missing fields and bad tokens`() {
        val tok = WebVectors.DEVICE_TOKEN
        val bad = listOf(
            "", "    ",
            "definitely not base64url ///",
            encode("[1,2,3]"),
            encode("""{"v":2,"srv":"https://x.com","email":"a@b.c","tok":"$tok"}"""),
            encode("""{"srv":"https://x.com","email":"a@b.c","tok":"$tok"}"""),
            encode("""{"v":1,"email":"a@b.c","tok":"$tok"}"""),
            encode("""{"v":1,"srv":"ftp://x.com","email":"a@b.c","tok":"$tok"}"""),
            encode("""{"v":1,"srv":"https://x.com","tok":"$tok"}"""),
            encode("""{"v":1,"srv":"https://x.com","email":"a@b.c"}"""),
            encode("""{"v":1,"srv":"https://x.com","email":"a@b.c","tok":"jwt-not-mpd"}"""),
        )
        for (payload in bad) {
            assertThrows("should reject: $payload", IllegalArgumentException::class.java) {
                QrPayload.parse(payload)
            }
        }
    }

    @Test
    fun `isDeviceToken matches the server token format`() {
        assertTrue(QrPayload.isDeviceToken(WebVectors.DEVICE_TOKEN))
        // Secret may contain '_' and '-' (base64url): positional split required.
        assertTrue(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_ab_-cd"))

        assertFalse(QrPayload.isDeviceToken(""))
        assertFalse(QrPayload.isDeviceToken("mpd_"))
        assertFalse(QrPayload.isDeviceToken("jwt_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_abc"))
        assertFalse(QrPayload.isDeviceToken("mpd_not-a-uuid_secretsecret"))
        assertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf")) // no secret
        assertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_")) // empty secret
        assertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_sec ret"))
        assertFalse(QrPayload.isDeviceToken("mpd_1c9c40b5-95a6-4be6-8d2f-14839e2a70cf_sec+ret"))
    }
}
