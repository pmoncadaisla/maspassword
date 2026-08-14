package com.maspassword.core

import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

/** The parsed contents of a device-pairing QR code. Carries NO key material. */
data class LinkPayload(
    val version: Int,
    /** Server origin, e.g. "https://vault.example.com" (no trailing slash). */
    val serverUrl: String,
    /** Account email — used for display; key derivation uses the session email. */
    val email: String,
    /** Device API token, "mpd_<uuid>_<base64url secret>". */
    val token: String,
)

/**
 * Parser for the pairing payload produced by `renderDevicePairing` in
 * web/app.js: `base64url(JSON({"v":1,"srv":origin,"email":...,"tok":"mpd_..."}))`
 * with '=' padding stripped. Every failure throws [IllegalArgumentException]
 * with a human-readable reason; nothing is ever guessed (fail closed).
 */
object QrPayload {

    const val SUPPORTED_VERSION = 1
    const val TOKEN_PREFIX = "mpd_"

    private val UUID_RE =
        Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)
    private val B64URL_RE = Regex("^[A-Za-z0-9_-]+$")

    /**
     * Parse a scanned or pasted pairing payload. Accepts the canonical
     * unpadded base64url form; tolerates '=' padding, surrounding whitespace
     * and standard-alphabet base64 (some share paths re-encode with +/).
     */
    fun parse(raw: String): LinkPayload {
        val compact = raw.filterNot { it.isWhitespace() }
        require(compact.isNotEmpty()) { "empty pairing code" }

        val normalized = compact.replace('+', '-').replace('/', '_').trimEnd('=')
        val jsonBytes = try {
            Base64.getUrlDecoder().decode(normalized)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("not a pairing code (invalid base64url)", e)
        }
        val json = try {
            JSONObject(String(jsonBytes, Charsets.UTF_8))
        } catch (e: JSONException) {
            throw IllegalArgumentException("not a pairing code (invalid JSON)", e)
        }

        val version = json.optInt("v", -1)
        require(version == SUPPORTED_VERSION) { "unsupported pairing version '$version' (expected $SUPPORTED_VERSION)" }

        val srv = json.optString("srv").trim().trimEnd('/')
        require(srv.startsWith("https://") || srv.startsWith("http://")) {
            "pairing code has no valid server URL"
        }

        val email = json.optString("email").trim()
        require(email.isNotEmpty()) { "pairing code has no email" }

        val token = json.optString("tok").trim()
        require(isDeviceToken(token)) { "pairing code has no valid device token" }

        return LinkPayload(version, srv, email, token)
    }

    /**
     * Shape check for a device token, mirroring `devicetoken.ParseID` on the
     * server: "mpd_" + 36-char UUID + "_" + non-empty base64url secret. The
     * split is positional because the secret may itself contain underscores.
     */
    fun isDeviceToken(raw: String): Boolean {
        if (!raw.startsWith(TOKEN_PREFIX)) return false
        val rest = raw.substring(TOKEN_PREFIX.length)
        if (rest.length < 38 || rest[36] != '_') return false
        val uuid = rest.substring(0, 36)
        val secret = rest.substring(37)
        return UUID_RE.matches(uuid) && B64URL_RE.matches(secret)
    }
}
