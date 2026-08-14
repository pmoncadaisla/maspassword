package com.maspassword.app.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.maspassword.app.App
import com.maspassword.app.Bg
import com.maspassword.app.R
import com.maspassword.app.net.ApiException
import com.maspassword.app.net.EncryptionNotSetUpException
import com.maspassword.app.net.WrongPasswordException
import com.maspassword.core.LinkPayload
import com.maspassword.core.QrPayload

/**
 * Device pairing. Input is either the QR from the web's "Linked devices"
 * modal, a pasted copy of that payload, or a raw `mpd_...` token plus a
 * manually typed server URL. The master password is asked ONCE, verified by
 * decrypting `encrypted_private_key` from GET /api/auth/session, and never
 * stored; only server/email/token are persisted (Keystore-encrypted).
 */
class LinkActivity : AppCompatActivity() {

    private lateinit var codeInput: EditText
    private lateinit var serverInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var statusText: TextView
    private lateinit var linkButton: Button
    private lateinit var progress: ProgressBar

    /** Parsed full payload, when the code field holds one. */
    private var payload: LinkPayload? = null

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let { codeInput.setText(it.trim()) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_link)

        codeInput = findViewById(R.id.link_code_input)
        serverInput = findViewById(R.id.link_server_input)
        passwordInput = findViewById(R.id.link_password_input)
        statusText = findViewById(R.id.link_status)
        linkButton = findViewById(R.id.link_button)
        progress = findViewById(R.id.link_progress)

        findViewById<Button>(R.id.link_scan_button).setOnClickListener {
            scanLauncher.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt(getString(R.string.link_scan_prompt))
                    .setBeepEnabled(false)
                    .setOrientationLocked(true),
            )
        }

        codeInput.doAfterTextChanged { onCodeChanged(it?.toString().orEmpty().trim()) }
        linkButton.setOnClickListener { attemptLink() }
        onCodeChanged("")
    }

    /** Re-evaluate the pasted/scanned value: full payload vs raw token. */
    private fun onCodeChanged(code: String) {
        payload = runCatching { QrPayload.parse(code) }.getOrNull()
        when {
            payload != null -> {
                serverInput.setText(payload!!.serverUrl)
                serverInput.isEnabled = false
                status(getString(R.string.link_payload_ok, payload!!.email), error = false)
            }
            QrPayload.isDeviceToken(code) -> {
                serverInput.isEnabled = true
                status(getString(R.string.link_token_needs_server), error = false)
            }
            code.isEmpty() -> {
                serverInput.isEnabled = true
                statusText.text = ""
            }
            else -> {
                serverInput.isEnabled = true
                status(getString(R.string.link_code_invalid), error = true)
            }
        }
    }

    private fun attemptLink() {
        val code = codeInput.text.toString().trim()
        val password = passwordInput.text.toString()
        val server = (payload?.serverUrl ?: serverInput.text.toString().trim()).trimEnd('/')
        val token = payload?.token ?: code

        if (!QrPayload.isDeviceToken(token)) {
            return status(getString(R.string.link_code_invalid), error = true)
        }
        if (!server.startsWith("https://") && !server.startsWith("http://")) {
            return status(getString(R.string.link_server_invalid), error = true)
        }
        if (password.isEmpty()) {
            return status(getString(R.string.link_password_required), error = true)
        }

        setBusy(true)
        val app = App.from(this)
        Bg.submit(work = { app.repo.linkAndUnlock(server, token, password) }) { result ->
            setBusy(false)
            result.fold(
                onSuccess = {
                    passwordInput.setText("")
                    startActivity(Intent(this, HomeActivity::class.java))
                    finish()
                },
                onFailure = { e -> status(describeError(e), error = true) },
            )
        }
    }

    private fun describeError(e: Throwable): String = when (e) {
        is WrongPasswordException -> getString(R.string.error_wrong_password)
        is EncryptionNotSetUpException -> getString(R.string.error_encryption_not_setup)
        is ApiException ->
            if (e.isUnauthorized) getString(R.string.error_token_rejected)
            else e.message ?: getString(R.string.error_generic)
        else -> e.message ?: getString(R.string.error_generic)
    }

    private fun status(message: String, error: Boolean) {
        statusText.text = message
        statusText.setTextColor(getColor(if (error) R.color.mp_error else R.color.mp_muted))
    }

    private fun setBusy(busy: Boolean) {
        progress.visibility = if (busy) View.VISIBLE else View.GONE
        linkButton.isEnabled = !busy
        codeInput.isEnabled = !busy
        passwordInput.isEnabled = !busy
        if (!busy) onCodeChanged(codeInput.text.toString().trim())
        else serverInput.isEnabled = false
    }
}
