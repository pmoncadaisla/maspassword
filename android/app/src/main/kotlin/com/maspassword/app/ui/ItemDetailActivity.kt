package com.maspassword.app.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.method.PasswordTransformationMethod
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.maspassword.app.App
import com.maspassword.app.R
import com.maspassword.app.Session
import com.maspassword.core.Totp

/**
 * Read-only item detail: copy username/password (sensitive clipboard),
 * reveal toggle, live RFC 6238 TOTP with countdown, notes, custom fields,
 * tags and attachment metadata. Renders exclusively from the in-memory
 * snapshot — nothing is fetched or written here.
 */
class ItemDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_ITEM_ID = "item_id"
    }

    private val totpHandler = Handler(Looper.getMainLooper())
    private var totpTick: Runnable? = null
    private var item: Session.DecryptedItem? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = App.from(this)
        val found = app.session.findItem(intent.getStringExtra(EXTRA_ITEM_ID).orEmpty())
        if (!app.session.isUnlocked || found == null) {
            finish() // locked meanwhile (or stale id): never render without keys
            return
        }
        item = found
        setContentView(R.layout.activity_item_detail)
        render(found)
    }

    private fun render(item: Session.DecryptedItem) {
        val d = item.data
        findViewById<TextView>(R.id.detail_title).text =
            d.title.ifBlank { getString(R.string.item_untitled) }
        findViewById<TextView>(R.id.detail_vault).text =
            getString(R.string.detail_vault, item.vaultName, typeLabel(d.type))

        // Username
        bindCopyRow(R.id.detail_username_row, R.id.detail_username, R.id.detail_username_copy,
            d.username, getString(R.string.field_username), sensitive = false)

        // Password (masked + reveal + sensitive copy)
        val pwRow = findViewById<View>(R.id.detail_password_row)
        if (d.password.isBlank()) {
            pwRow.visibility = View.GONE
        } else {
            val pwText = findViewById<TextView>(R.id.detail_password)
            pwText.text = d.password
            pwText.transformationMethod = PasswordTransformationMethod.getInstance()
            findViewById<ImageButton>(R.id.detail_password_reveal).setOnClickListener {
                pwText.transformationMethod =
                    if (pwText.transformationMethod == null) PasswordTransformationMethod.getInstance()
                    else null
            }
            findViewById<ImageButton>(R.id.detail_password_copy).setOnClickListener {
                ClipboardX.copy(this, getString(R.string.field_password), d.password, sensitive = true)
                toast(R.string.copied_sensitive)
            }
        }

        // URL
        bindCopyRow(R.id.detail_url_row, R.id.detail_url, R.id.detail_url_copy,
            d.url, getString(R.string.field_url), sensitive = false)

        // TOTP
        val totpRow = findViewById<View>(R.id.detail_totp_row)
        if (d.totpSecret.isBlank()) {
            totpRow.visibility = View.GONE
        } else {
            findViewById<TextView>(R.id.detail_totp_code).setOnClickListener {
                runCatching { Totp.generate(d.totpSecret) }.onSuccess {
                    ClipboardX.copy(this, getString(R.string.field_totp), it.code, sensitive = true)
                    toast(R.string.copied_sensitive)
                }
            }
        }

        // Notes
        val notesRow = findViewById<View>(R.id.detail_notes_row)
        if (d.notes.isBlank()) notesRow.visibility = View.GONE
        else findViewById<TextView>(R.id.detail_notes).text = d.notes

        // Tags
        val tagsRow = findViewById<View>(R.id.detail_tags_row)
        if (d.tags.isEmpty()) tagsRow.visibility = View.GONE
        else findViewById<TextView>(R.id.detail_tags).text = d.tags.joinToString("   ") { "#$it" }

        // Custom fields (hidden ones masked until tapped)
        val cfContainer = findViewById<LinearLayout>(R.id.detail_custom_fields)
        if (d.customFields.isEmpty()) {
            findViewById<View>(R.id.detail_custom_fields_row).visibility = View.GONE
        } else {
            for (cf in d.customFields) {
                val row = layoutInflater.inflate(R.layout.row_custom_field, cfContainer, false)
                row.findViewById<TextView>(R.id.cf_label).text =
                    cf.label.ifBlank { getString(R.string.field_custom) }
                val valueView = row.findViewById<TextView>(R.id.cf_value)
                valueView.text = cf.value
                if (cf.hidden) {
                    valueView.transformationMethod = PasswordTransformationMethod.getInstance()
                    valueView.setOnClickListener {
                        valueView.transformationMethod =
                            if (valueView.transformationMethod == null) PasswordTransformationMethod.getInstance()
                            else null
                    }
                }
                row.findViewById<ImageButton>(R.id.cf_copy).setOnClickListener {
                    ClipboardX.copy(this, cf.label, cf.value, sensitive = cf.hidden)
                    toast(if (cf.hidden) R.string.copied_sensitive else R.string.copied)
                }
                cfContainer.addView(row)
            }
        }

        // Attachments: metadata only. They live INSIDE the encrypted blob; the
        // app intentionally does not export files (see README limitations).
        val attRow = findViewById<View>(R.id.detail_attachments_row)
        if (d.attachments.isEmpty()) {
            attRow.visibility = View.GONE
        } else {
            findViewById<TextView>(R.id.detail_attachments).text =
                d.attachments.joinToString("\n") { "${it.name}  (${formatSize(it.size)})" }
        }
    }

    private fun bindCopyRow(
        rowId: Int, textId: Int, copyId: Int, value: String, label: String, sensitive: Boolean,
    ) {
        val row = findViewById<View>(rowId)
        if (value.isBlank()) {
            row.visibility = View.GONE
            return
        }
        findViewById<TextView>(textId).text = value
        findViewById<ImageButton>(copyId).setOnClickListener {
            ClipboardX.copy(this, label, value, sensitive)
            toast(if (sensitive) R.string.copied_sensitive else R.string.copied)
        }
    }

    override fun onStart() {
        super.onStart()
        val secret = item?.data?.totpSecret.orEmpty()
        if (secret.isNotBlank()) startTotpTicker(secret)
    }

    override fun onStop() {
        super.onStop()
        totpTick?.let { totpHandler.removeCallbacks(it) }
        totpTick = null
    }

    /** Recompute the code every second; RFC 6238 SHA-1/30s/6 digits (see :core Totp). */
    private fun startTotpTicker(secret: String) {
        val codeView = findViewById<TextView>(R.id.detail_totp_code)
        val remainView = findViewById<TextView>(R.id.detail_totp_remaining)
        val bar = findViewById<ProgressBar>(R.id.detail_totp_progress)
        bar.max = Totp.DEFAULT_PERIOD_SECONDS
        val tick = object : Runnable {
            override fun run() {
                runCatching { Totp.generate(secret) }.fold(
                    onSuccess = { c ->
                        codeView.text = "${c.code.take(3)} ${c.code.drop(3)}"
                        remainView.text = getString(R.string.totp_remaining, c.remainingSeconds)
                        bar.progress = c.remainingSeconds
                    },
                    onFailure = {
                        codeView.text = getString(R.string.totp_invalid)
                        remainView.text = ""
                    },
                )
                totpHandler.postDelayed(this, 1000)
            }
        }
        totpTick = tick
        tick.run()
    }

    private fun typeLabel(type: String): String = when (type) {
        "card" -> getString(R.string.type_card)
        "note" -> getString(R.string.type_note)
        "identity" -> getString(R.string.type_identity)
        else -> getString(R.string.type_login)
    }

    private fun formatSize(bytes: Long): String = when {
        bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1024 -> "%.0f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }

    private fun toast(resId: Int) {
        Toast.makeText(this, resId, Toast.LENGTH_SHORT).show()
    }
}
