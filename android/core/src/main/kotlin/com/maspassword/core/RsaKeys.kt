package com.maspassword.core

import org.json.JSONException
import org.json.JSONObject
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * RSA side of the shared-vault scheme, matching `web/crypto.js`:
 *
 *  - The account keypair is RSA-OAEP 4096 with SHA-256 (WebCrypto
 *    `generateKeyPair`). The PRIVATE key is stored server-side as a **JWK
 *    JSON string** (WebCrypto `exportKey('jwk', ...)`) encrypted with the
 *    derived AES key via the standard AES-GCM envelope — i.e.
 *    `encrypted_private_key = encrypt(derivedKey, JSON.stringify(privateKeyJwk))`.
 *    It is NOT PKCS#8: this module imports the JWK parameters directly.
 *  - Shared-vault AES keys travel as RSA-OAEP ciphertexts of the vault key's
 *    base64 STRING (`encryptWithPublicKey(pub, vaultKeyBase64)`), so
 *    unwrapping = OAEP-decrypt -> UTF-8 string -> base64 -> 32 key bytes.
 *  - WebCrypto RSA-OAEP with `hash: SHA-256` uses SHA-256 for BOTH the OAEP
 *    digest and MGF1, with an empty label. JCE is told so explicitly via
 *    OAEPParameterSpec (never trust provider defaults for MGF1).
 */
object RsaKeys {

    /** Parse a WebCrypto RSA private JWK (JSON string) into an RSAPrivateKey. */
    fun privateKeyFromJwk(jwkJson: String): RSAPrivateKey {
        val jwk = try {
            JSONObject(jwkJson)
        } catch (e: JSONException) {
            throw CryptoException("private key blob is not JWK JSON", e)
        }
        val kty = jwk.optString("kty")
        if (kty != "RSA") throw CryptoException("unsupported JWK kty '$kty' (expected RSA)")

        fun param(name: String): BigInteger {
            val b64u = if (jwk.isNull(name)) "" else jwk.optString(name)
            if (b64u.isEmpty()) throw CryptoException("JWK is missing parameter '$name'")
            val bytes = try {
                Base64.getUrlDecoder().decode(b64u)
            } catch (e: IllegalArgumentException) {
                throw CryptoException("JWK parameter '$name' is not base64url", e)
            }
            return BigInteger(1, bytes)
        }

        val hasCrt = !jwk.isNull("p") && !jwk.isNull("q") && !jwk.isNull("dp") &&
            !jwk.isNull("dq") && !jwk.isNull("qi")
        val spec = if (hasCrt) {
            RSAPrivateCrtKeySpec(
                param("n"), param("e"), param("d"),
                param("p"), param("q"),
                param("dp"), param("dq"), param("qi"),
            )
        } else {
            RSAPrivateKeySpec(param("n"), param("d"))
        }
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec) as RSAPrivateKey
        } catch (e: GeneralSecurityException) {
            throw CryptoException("invalid RSA private key parameters", e)
        }
    }

    /**
     * Decrypt `encrypted_private_key` (from GET /api/auth/session) with the
     * derived AES key and import the contained JWK. Mirrors
     * `decryptPrivateKey` in web/crypto.js. This doubles as the master
     * password verification: a wrong password fails the GCM tag check.
     */
    fun decryptPrivateKey(derivedKey: SecretKey, encryptedPrivateKey: String): RSAPrivateKey =
        privateKeyFromJwk(VaultCrypto.decrypt(derivedKey, encryptedPrivateKey))

    /** RSA-OAEP(SHA-256/MGF1-SHA-256) decrypt base64 ciphertext -> UTF-8 string. */
    fun rsaOaepDecryptToString(privateKey: RSAPrivateKey, encodedCiphertext: String): String {
        val ct = try {
            Base64.getDecoder().decode(encodedCiphertext.trim())
        } catch (e: IllegalArgumentException) {
            throw CryptoException("RSA ciphertext is not valid base64", e)
        }
        try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            val oaep = OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT,
            )
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaep)
            return String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            throw CryptoException("RSA-OAEP decryption failed", e)
        }
    }

    /**
     * Unwrap a shared vault's AES key: `encrypted_vault_key` from
     * GET /api/vaults/:id/key -> OAEP decrypt -> base64 string -> AES key.
     * Mirrors `decryptWithPrivateKey` + `importVaultKey` in web/app.js
     * `getVaultDecryptionKey`.
     */
    fun unwrapVaultKey(privateKey: RSAPrivateKey, encryptedVaultKey: String): SecretKey =
        VaultCrypto.importVaultKey(rsaOaepDecryptToString(privateKey, encryptedVaultKey))
}
