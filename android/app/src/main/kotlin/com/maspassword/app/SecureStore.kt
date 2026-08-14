package com.maspassword.app

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Persistent link state, stored in EncryptedSharedPreferences whose master
 * key lives in the Android Keystore (AES-256-GCM, non-exportable).
 *
 * What is stored here: server URL, account email, device API token,
 * biometric preference. What is NEVER stored (anywhere, ever): the master
 * password, the derived AES key, the RSA private key, vault keys, plaintext
 * items. Those exist only in [Session] (RAM) while the app is unlocked.
 */
class SecureStore(context: Context) {

    private val prefs: SharedPreferences = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "maspassword_link",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    val serverUrl: String? get() = prefs.getString(KEY_SERVER, null)
    val email: String? get() = prefs.getString(KEY_EMAIL, null)
    val deviceToken: String? get() = prefs.getString(KEY_TOKEN, null)

    val isLinked: Boolean
        get() = !serverUrl.isNullOrEmpty() && !deviceToken.isNullOrEmpty()

    var biometricEnabled: Boolean
        get() = prefs.getBoolean(KEY_BIOMETRIC, false)
        set(value) = prefs.edit { putBoolean(KEY_BIOMETRIC, value) }

    /** Persist a verified link. Called only AFTER the master password proved right. */
    fun saveLink(serverUrl: String, email: String, deviceToken: String) {
        prefs.edit {
            putString(KEY_SERVER, serverUrl.trimEnd('/'))
            putString(KEY_EMAIL, email)
            putString(KEY_TOKEN, deviceToken)
        }
    }

    /** Unlink this device (the token should also be revoked from the web UI). */
    fun clearLink() {
        prefs.edit { clear() }
    }

    private companion object {
        const val KEY_SERVER = "server_url"
        const val KEY_EMAIL = "email"
        const val KEY_TOKEN = "device_token"
        const val KEY_BIOMETRIC = "biometric_enabled"
    }
}
