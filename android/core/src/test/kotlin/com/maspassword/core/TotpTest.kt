package com.maspassword.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TotpTest {

    // RFC 6238 Appendix B SHA-1 secret: ASCII "12345678901234567890".
    private val rfcSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Test
    fun `base32 decodes the RFC secret`() {
        assertArrayEquals(
            "12345678901234567890".toByteArray(Charsets.US_ASCII),
            Totp.base32Decode(rfcSecretBase32),
        )
    }

    @Test
    fun `base32 ignores case spaces dashes and padding - like the web`() {
        val messy = "gezd gnbv-gy3t qojq=GEZD GNBV GY3T QOJQ=="
        assertArrayEquals(Totp.base32Decode(rfcSecretBase32), Totp.base32Decode(messy))
        // Non-alphabet chars (0, 1, 8, 9) are silently skipped, like the web.
        assertArrayEquals(Totp.base32Decode("JBSWY3DPEHPK3PXP"), Totp.base32Decode("JBSWY3DP0EHPK3PXP1"))
    }

    // RFC 6238 Appendix B test vectors (HMAC-SHA-1). The RFC lists 8-digit
    // codes; 6-digit codes are the same value mod 10^6, which is also exactly
    // what web/crypto.js computes.
    @Test
    fun `rfc 6238 sha1 vectors`() {
        val cases = mapOf(
            59L to "287082",          // 8-digit 94287082
            1111111109L to "081804",  // 8-digit 07081804
            1111111111L to "050471",  // 8-digit 14050471
            1234567890L to "005924",  // 8-digit 89005924
            2000000000L to "279037",  // 8-digit 69279037
            20000000000L to "353130", // 8-digit 65353130
        )
        for ((t, expected) in cases) {
            assertEquals("at t=$t", expected, Totp.generate(rfcSecretBase32, t).code)
        }
    }

    @Test
    fun `eight digit codes match the rfc table`() {
        assertEquals("94287082", Totp.generate(rfcSecretBase32, 59, 30, 8).code)
        assertEquals("65353130", Totp.generate(rfcSecretBase32, 20000000000L, 30, 8).code)
    }

    @Test
    fun `remaining seconds counts down within the period`() {
        assertEquals(1, Totp.generate(rfcSecretBase32, 59).remainingSeconds)
        assertEquals(30, Totp.generate(rfcSecretBase32, 60).remainingSeconds)
        assertEquals(29, Totp.generate(rfcSecretBase32, 61).remainingSeconds)
    }

    @Test
    fun `code is stable within a period and changes across the boundary`() {
        val a = Totp.generate(rfcSecretBase32, 30).code
        val b = Totp.generate(rfcSecretBase32, 59).code
        val c = Totp.generate(rfcSecretBase32, 60).code
        assertEquals(a, b)
        org.junit.Assert.assertNotEquals(b, c)
    }

    @Test
    fun `codes are always zero-padded to six digits`() {
        // t=1234567890 produces 005924 — leading zeros preserved.
        assertEquals(6, Totp.generate(rfcSecretBase32, 1234567890L).code.length)
        assertEquals("005924", Totp.generate(rfcSecretBase32, 1234567890L).code)
    }

    @Test
    fun `empty or all-invalid secrets are rejected`() {
        assertThrows(IllegalArgumentException::class.java) { Totp.generate("", 59) }
        assertThrows(IllegalArgumentException::class.java) { Totp.generate("0189!", 59) }
    }
}
