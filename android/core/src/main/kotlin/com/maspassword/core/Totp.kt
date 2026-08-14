package com.maspassword.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 6238 TOTP, matching `generateTOTP` in web/crypto.js:
 * HMAC-SHA1, 30-second period, 6 digits, Base32 secret.
 *
 * The Base32 decoder mirrors the web one exactly: whitespace, '=' padding and
 * '-' separators are stripped, input is uppercased, any other non-alphabet
 * character is skipped, and trailing bits that do not fill a byte are dropped.
 */
object Totp {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    const val DEFAULT_PERIOD_SECONDS = 30
    const val DEFAULT_DIGITS = 6

    /** A generated code plus how many seconds it remains valid. */
    data class Code(val code: String, val remainingSeconds: Int)

    fun base32Decode(secret: String): ByteArray {
        val out = ByteArrayOutputStream()
        var buffer = 0
        var bitCount = 0
        for (raw in secret.uppercase()) {
            if (raw.isWhitespace() || raw == '=' || raw == '-') continue
            val value = ALPHABET.indexOf(raw)
            if (value < 0) continue // mirror web: silently skip unknown chars
            buffer = (buffer shl 5) or value
            bitCount += 5
            if (bitCount >= 8) {
                bitCount -= 8
                out.write((buffer ushr bitCount) and 0xFF)
            }
        }
        return out.toByteArray()
    }

    /**
     * Generate the code for [unixSeconds] (defaults to now). The counter is
     * encoded as 8-byte big-endian; the web writes only the low 32 bits, which
     * is identical for any timestamp before the year ~6000.
     */
    @JvmOverloads
    fun generate(
        secret: String,
        unixSeconds: Long = System.currentTimeMillis() / 1000,
        periodSeconds: Int = DEFAULT_PERIOD_SECONDS,
        digits: Int = DEFAULT_DIGITS,
    ): Code {
        require(periodSeconds > 0) { "period must be positive" }
        require(digits in 6..8) { "digits must be 6..8" }
        val keyBytes = base32Decode(secret)
        if (keyBytes.isEmpty()) throw IllegalArgumentException("TOTP secret decodes to zero bytes")

        val counter = unixSeconds / periodSeconds
        val remaining = (periodSeconds - (unixSeconds % periodSeconds)).toInt()

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(keyBytes, "RAW"))
        val hmac = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())

        // RFC 4226 dynamic truncation.
        val offset = hmac[hmac.size - 1].toInt() and 0x0f
        val binary = ((hmac[offset].toInt() and 0x7f) shl 24) or
            ((hmac[offset + 1].toInt() and 0xff) shl 16) or
            ((hmac[offset + 2].toInt() and 0xff) shl 8) or
            (hmac[offset + 3].toInt() and 0xff)

        var modulus = 1
        repeat(digits) { modulus *= 10 }
        val code = (binary % modulus).toString().padStart(digits, '0')
        return Code(code, remaining)
    }
}
