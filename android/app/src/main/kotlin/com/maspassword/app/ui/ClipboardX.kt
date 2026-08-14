package com.maspassword.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import com.maspassword.app.Bg

/** Clipboard helper for secrets. */
object ClipboardX {

    private const val CLEAR_AFTER_MS = 45_000L
    // ClipDescription.EXTRA_IS_SENSITIVE is API 33; the literal is honored by
    // earlier keyboard/clipboard UIs that know it, ignored otherwise.
    private const val EXTRA_IS_SENSITIVE_COMPAT = "android.content.extra.IS_SENSITIVE"

    /**
     * Copy [value]; when [sensitive], flag it so the system does not show a
     * preview (API 33+) and best-effort clear it after 45 s — only if the
     * clipboard still holds this exact value (never wipe newer content).
     * The auto-clear only fires while the process is alive; the flag also
     * keeps sensitive values out of the clipboard sync/history on modern
     * Android.
     */
    fun copy(context: Context, label: String, value: String, sensitive: Boolean) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, value)
        if (sensitive) {
            val key = if (Build.VERSION.SDK_INT >= 33) {
                android.content.ClipDescription.EXTRA_IS_SENSITIVE
            } else {
                EXTRA_IS_SENSITIVE_COMPAT
            }
            clip.description.extras = PersistableBundle().apply { putBoolean(key, true) }
        }
        cm.setPrimaryClip(clip)

        if (sensitive) {
            Bg.onMainDelayed(CLEAR_AFTER_MS) {
                runCatching {
                    val current = cm.primaryClip?.getItemAt(0)?.text?.toString()
                    if (current == value) {
                        if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
                        else cm.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                }
            }
        }
    }
}
