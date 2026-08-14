package com.maspassword.core

import org.json.JSONException
import org.json.JSONObject

/** A custom field stored inside the encrypted blob: {label, value, hidden}. */
data class CustomField(val label: String, val value: String, val hidden: Boolean)

/**
 * An attachment stored INSIDE the encrypted blob (see web/attachments.js):
 * {name, type, size, data} where data is base64 without any "data:" prefix.
 */
data class Attachment(val name: String, val type: String, val size: Long, val data: String)

/**
 * The decrypted item JSON, as written by `saveItem` in web/app.js. Read-only:
 * the Android app never edits items, so unknown fields (card_*, id_*, icon,
 * pwChangedAt, ...) are preserved verbatim in [raw] instead of being modeled.
 *
 * Known fields: type, title, username, password, url, notes, totp_secret,
 * tags, favorite, customFields, attachments. Types outside
 * {login, card, note, identity} normalize to "login", exactly like the web's
 * `itemType()`.
 */
data class ItemData(
    val type: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val notes: String,
    val totpSecret: String,
    val tags: List<String>,
    val favorite: Boolean,
    val customFields: List<CustomField>,
    val attachments: List<Attachment>,
    /** The original decrypted JSON, untouched. */
    val raw: String,
) {
    val isLogin: Boolean get() = type == TYPE_LOGIN

    companion object {
        const val TYPE_LOGIN = "login"
        val KNOWN_TYPES = setOf("login", "card", "note", "identity")

        /** Parse decrypted item JSON. Throws [IllegalArgumentException] if not a JSON object. */
        fun fromJson(json: String): ItemData {
            val o = try {
                JSONObject(json)
            } catch (e: JSONException) {
                throw IllegalArgumentException("item data is not a JSON object", e)
            }

            fun str(name: String): String = if (o.isNull(name)) "" else o.optString(name)

            val rawType = str("type")
            val type = if (rawType in KNOWN_TYPES) rawType else TYPE_LOGIN

            val tags = mutableListOf<String>()
            o.optJSONArray("tags")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val t = if (arr.isNull(i)) "" else arr.optString(i)
                    if (t.isNotBlank()) tags.add(t)
                }
            }

            val customFields = mutableListOf<CustomField>()
            o.optJSONArray("customFields")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val cf = arr.optJSONObject(i) ?: continue
                    customFields.add(
                        CustomField(
                            label = if (cf.isNull("label")) "" else cf.optString("label"),
                            value = if (cf.isNull("value")) "" else cf.optString("value"),
                            hidden = cf.optBoolean("hidden", false),
                        ),
                    )
                }
            }

            val attachments = mutableListOf<Attachment>()
            o.optJSONArray("attachments")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val a = arr.optJSONObject(i) ?: continue
                    attachments.add(
                        Attachment(
                            name = if (a.isNull("name")) "file" else a.optString("name", "file"),
                            type = if (a.isNull("type")) "" else a.optString("type"),
                            size = a.optLong("size", 0L),
                            data = if (a.isNull("data")) "" else a.optString("data"),
                        ),
                    )
                }
            }

            return ItemData(
                type = type,
                title = str("title"),
                username = str("username"),
                password = str("password"),
                url = str("url"),
                notes = str("notes"),
                totpSecret = str("totp_secret"),
                tags = tags,
                favorite = o.optBoolean("favorite", false),
                customFields = customFields,
                attachments = attachments,
                raw = json,
            )
        }
    }

    /** Case-insensitive search across title/username/url/notes/tags. */
    fun matchesQuery(query: String): Boolean {
        if (query.isBlank()) return true
        val q = query.trim().lowercase()
        return title.lowercase().contains(q) ||
            username.lowercase().contains(q) ||
            url.lowercase().contains(q) ||
            notes.lowercase().contains(q) ||
            tags.any { it.lowercase().contains(q) }
    }
}
