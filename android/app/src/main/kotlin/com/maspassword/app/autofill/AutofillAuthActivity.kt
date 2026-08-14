package com.maspassword.app.autofill

import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.RemoteViews
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.maspassword.app.App
import com.maspassword.app.Bg
import com.maspassword.app.R
import com.maspassword.app.Session
import com.maspassword.app.net.WrongPasswordException
import com.maspassword.app.ui.BiometricGate
import com.maspassword.app.ui.ItemAdapter

/**
 * The authentication half of autofill, launched by the system from the
 * PendingIntents the service registered. Three modes:
 *
 *  - MODE_CONFIRM: an item was already chosen from the suggestion list;
 *    require biometric / device credential, then return the filled Dataset.
 *  - MODE_UNLOCK: the vault was locked; ask the master password, load items,
 *    then show the picker (domain matches first).
 *  - MODE_PICK: unlocked but nothing auto-matched (native app / unknown
 *    domain); show the searchable picker directly (behind the biometric gate
 *    when enabled).
 *
 * Results are handed back via EXTRA_AUTHENTICATION_RESULT: a [Dataset] for
 * dataset-level auth, a [FillResponse] for response-level auth.
 */
class AutofillAuthActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_MODE = "mode"
        const val EXTRA_USERNAME_ID = "username_id"
        const val EXTRA_PASSWORD_ID = "password_id"
        const val EXTRA_WEB_DOMAIN = "web_domain"
        const val EXTRA_ITEM_ID = "item_id"
        const val MODE_CONFIRM = "confirm"
        const val MODE_UNLOCK = "unlock"
        const val MODE_PICK = "pick"
    }

    private var usernameId: AutofillId? = null
    private var passwordId: AutofillId? = null
    private var webDomain: String? = null

    private lateinit var titleView: TextView
    private lateinit var passwordBox: View
    private lateinit var passwordInput: EditText
    private lateinit var statusText: TextView
    private lateinit var pickerBox: View
    private lateinit var progress: ProgressBar
    private lateinit var adapter: ItemAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_autofill_auth)

        usernameId = intent.getParcelableExtra(EXTRA_USERNAME_ID)
        passwordId = intent.getParcelableExtra(EXTRA_PASSWORD_ID)
        webDomain = intent.getStringExtra(EXTRA_WEB_DOMAIN)

        titleView = findViewById(R.id.aa_title)
        passwordBox = findViewById(R.id.aa_password_box)
        passwordInput = findViewById(R.id.aa_password_input)
        statusText = findViewById(R.id.aa_status)
        pickerBox = findViewById(R.id.aa_picker_box)
        progress = findViewById(R.id.aa_progress)

        adapter = ItemAdapter { item -> finishWithDataset(item) }
        findViewById<RecyclerView>(R.id.aa_list).apply {
            layoutManager = LinearLayoutManager(this@AutofillAuthActivity)
            adapter = this@AutofillAuthActivity.adapter
        }
        findViewById<EditText>(R.id.aa_search).doAfterTextChanged {
            adapter.filter(it?.toString().orEmpty())
        }

        val app = App.from(this)
        when (intent.getStringExtra(EXTRA_MODE)) {
            MODE_CONFIRM -> {
                val item = app.session.findItem(intent.getStringExtra(EXTRA_ITEM_ID).orEmpty())
                if (item == null || !app.session.isUnlocked) return cancel()
                confirmThenReturn(item)
            }
            MODE_UNLOCK -> showPasswordForm()
            MODE_PICK -> {
                if (!app.session.isUnlocked) return showPasswordForm()
                gateThenPick()
            }
            else -> cancel()
        }
    }

    // --- MODE_CONFIRM ------------------------------------------------------

    private fun confirmThenReturn(item: Session.DecryptedItem) {
        titleView.text = getString(R.string.autofill_confirm_title, item.data.title)
        if (BiometricGate.available(this)) {
            BiometricGate.prompt(
                this, getString(R.string.autofill_confirm_prompt), item.data.title,
            ) { ok -> if (ok) finishWithDataset(item) else cancel() }
        } else {
            // No biometrics and no device credential: explicit tap instead.
            passwordBox.visibility = View.GONE
            pickerBox.visibility = View.GONE
            val fillButton = findViewById<Button>(R.id.aa_fill_button)
            fillButton.visibility = View.VISIBLE
            fillButton.text = getString(R.string.autofill_fill_button, item.data.title)
            fillButton.setOnClickListener { finishWithDataset(item) }
        }
    }

    // --- MODE_UNLOCK -------------------------------------------------------

    private fun showPasswordForm() {
        titleView.text = getString(R.string.autofill_unlock_title)
        passwordBox.visibility = View.VISIBLE
        pickerBox.visibility = View.GONE
        findViewById<Button>(R.id.aa_unlock_button).setOnClickListener {
            val password = passwordInput.text.toString()
            if (password.isEmpty()) return@setOnClickListener
            val app = App.from(this)
            progress.visibility = View.VISIBLE
            Bg.submit(work = {
                app.repo.unlock(password)
                app.repo.loadAll(forceRefresh = false)
            }) { result ->
                progress.visibility = View.GONE
                result.fold(
                    onSuccess = {
                        passwordInput.setText("")
                        showPicker()
                    },
                    onFailure = { e ->
                        statusText.text = if (e is WrongPasswordException) {
                            getString(R.string.error_wrong_password)
                        } else {
                            e.message ?: getString(R.string.error_generic)
                        }
                    },
                )
            }
        }
    }

    // --- MODE_PICK ---------------------------------------------------------

    private fun gateThenPick() {
        val app = App.from(this)
        if (app.store.biometricEnabled && BiometricGate.available(this)) {
            BiometricGate.prompt(this, getString(R.string.biometric_title), webDomain) { ok ->
                if (ok) loadThenShowPicker() else cancel()
            }
        } else {
            loadThenShowPicker()
        }
    }

    private fun loadThenShowPicker() {
        val app = App.from(this)
        progress.visibility = View.VISIBLE
        Bg.submit(work = { app.repo.loadAll(forceRefresh = false) }) { result ->
            progress.visibility = View.GONE
            result.fold(onSuccess = { showPicker() }, onFailure = { cancel() })
        }
    }

    /** Domain matches first, then every login item (searchable). */
    private fun showPicker() {
        val app = App.from(this)
        passwordBox.visibility = View.GONE
        pickerBox.visibility = View.VISIBLE
        titleView.text = if (webDomain != null) {
            getString(R.string.autofill_pick_title_domain, webDomain)
        } else {
            getString(R.string.autofill_pick_title)
        }
        val matched = app.repo.matchesForDomain(webDomain)
        val all = app.session.snapshot?.items.orEmpty().filter { it.data.isLogin }
        adapter.submit((matched + (all - matched.toSet())))
    }

    // --- Results -----------------------------------------------------------

    private fun finishWithDataset(item: Session.DecryptedItem) {
        val dataset = buildDataset(item) ?: return cancel()
        val result = Intent().apply {
            val mode = intent.getStringExtra(EXTRA_MODE)
            if (mode == MODE_CONFIRM) {
                // Dataset-level authentication: return the unlocked Dataset.
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)
            } else {
                // Response-level authentication: return a full FillResponse.
                putExtra(
                    AutofillManager.EXTRA_AUTHENTICATION_RESULT,
                    FillResponse.Builder().addDataset(dataset).build(),
                )
            }
        }
        setResult(RESULT_OK, result)
        finish()
    }

    @Suppress("DEPRECATION")
    private fun buildDataset(item: Session.DecryptedItem): Dataset? {
        val uId = usernameId
        val pId = passwordId
        if (uId == null && pId == null) return null
        val pres = RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.af_title, item.data.title.ifBlank { getString(R.string.item_untitled) })
            setTextViewText(R.id.af_subtitle, item.data.username)
        }
        return Dataset.Builder().apply {
            uId?.let { setValue(it, AutofillValue.forText(item.data.username), pres) }
            pId?.let { setValue(it, AutofillValue.forText(item.data.password), pres) }
        }.build()
    }

    private fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }
}
