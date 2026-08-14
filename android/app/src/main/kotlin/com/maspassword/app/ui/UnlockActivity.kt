package com.maspassword.app.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.maspassword.app.App
import com.maspassword.app.Bg
import com.maspassword.app.R
import com.maspassword.app.net.ApiException
import com.maspassword.app.net.WrongPasswordException

/**
 * Master password re-prompt for a linked device (after process death or an
 * explicit Lock). Biometrics deliberately cannot appear here: with no key in
 * memory there is nothing a fingerprint could unlock — see BiometricGate.
 */
class UnlockActivity : AppCompatActivity() {

    private lateinit var passwordInput: EditText
    private lateinit var statusText: TextView
    private lateinit var unlockButton: Button
    private lateinit var progress: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_unlock)
        val app = App.from(this)

        if (!app.store.isLinked) {
            startActivity(Intent(this, LinkActivity::class.java))
            finish()
            return
        }

        findViewById<TextView>(R.id.unlock_account).text =
            getString(R.string.unlock_account, app.store.email ?: "?", app.store.serverUrl ?: "?")
        passwordInput = findViewById(R.id.unlock_password_input)
        statusText = findViewById(R.id.unlock_status)
        unlockButton = findViewById(R.id.unlock_button)
        progress = findViewById(R.id.unlock_progress)

        unlockButton.setOnClickListener { attemptUnlock() }
        findViewById<Button>(R.id.unlock_unlink_button).setOnClickListener { confirmUnlink() }
    }

    private fun attemptUnlock() {
        val password = passwordInput.text.toString()
        if (password.isEmpty()) {
            statusText.text = getString(R.string.link_password_required)
            return
        }
        setBusy(true)
        val app = App.from(this)
        Bg.submit(work = { app.repo.unlock(password) }) { result ->
            setBusy(false)
            result.fold(
                onSuccess = {
                    passwordInput.setText("")
                    startActivity(Intent(this, HomeActivity::class.java))
                    finish()
                },
                onFailure = { e ->
                    statusText.text = when {
                        e is WrongPasswordException -> getString(R.string.error_wrong_password)
                        e is ApiException && e.isUnauthorized -> getString(R.string.error_token_revoked)
                        else -> e.message ?: getString(R.string.error_generic)
                    }
                },
            )
        }
    }

    private fun confirmUnlink() {
        AlertDialog.Builder(this)
            .setTitle(R.string.unlink_title)
            .setMessage(R.string.unlink_message)
            .setPositiveButton(R.string.unlink_confirm) { _, _ ->
                val app = App.from(this)
                app.session.lock()
                app.store.clearLink()
                startActivity(Intent(this, LinkActivity::class.java))
                finish()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun setBusy(busy: Boolean) {
        progress.visibility = if (busy) View.VISIBLE else View.GONE
        unlockButton.isEnabled = !busy
        passwordInput.isEnabled = !busy
    }
}
