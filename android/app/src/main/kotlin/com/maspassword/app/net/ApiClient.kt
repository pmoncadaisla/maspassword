package com.maspassword.app.net

import com.maspassword.core.ApiModels
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** A server-reported or transport-level API failure. */
class ApiException(
    val code: String,
    message: String,
    val httpStatus: Int = 0,
) : Exception(message) {
    val isUnauthorized: Boolean get() = httpStatus == 401
}

/**
 * Minimal HTTP client on HttpURLConnection — no OkHttp, no TLS pinning
 * surprises, nothing to audit beyond the platform. The app only ever needs
 * authenticated GETs (it is a read-only client), sent with the device token:
 * `Authorization: Bearer mpd_...` (see internal/middleware/device.go).
 *
 * IAP note: redirects are NOT followed. A Google-IAP-fronted deployment
 * answers API calls with a 302 to accounts.google.com — surfaced here as a
 * clear IAP_BLOCKED error instead of a confusing JSON parse failure
 * (see README "IAP caveat").
 */
class ApiClient(baseUrl: String, private val deviceToken: String) {

    private val base = baseUrl.trimEnd('/')

    fun get(path: String): String {
        val conn = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            instanceFollowRedirects = false
            connectTimeout = 15_000
            readTimeout = 20_000
            setRequestProperty("Authorization", "Bearer $deviceToken")
            setRequestProperty("Accept", "application/json")
        }
        try {
            val status = try {
                conn.responseCode
            } catch (e: IOException) {
                throw ApiException("NETWORK", "cannot reach $base (${e.message})")
            }

            if (status in 300..399) {
                throw ApiException(
                    "IAP_BLOCKED",
                    "$base redirected the API call to a login page — an IAP-protected " +
                        "deployment cannot serve non-browser clients (see android/README.md)",
                    status,
                )
            }

            val body = try {
                (if (status >= 400) conn.errorStream else conn.inputStream)
                    ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            } catch (e: IOException) {
                throw ApiException("NETWORK", "error reading response from $base (${e.message})", status)
            }

            if (status >= 400) {
                val err = ApiModels.parseError(body)
                throw ApiException(err?.code ?: "HTTP_$status", err?.message ?: "request failed (HTTP $status)", status)
            }

            val contentType = conn.contentType ?: ""
            if (contentType.contains("text/html", ignoreCase = true)) {
                throw ApiException(
                    "IAP_BLOCKED",
                    "$base answered with an HTML page instead of JSON — likely an " +
                        "IAP/SSO interstitial (see android/README.md)",
                    status,
                )
            }
            return body
        } finally {
            conn.disconnect()
        }
    }
}
