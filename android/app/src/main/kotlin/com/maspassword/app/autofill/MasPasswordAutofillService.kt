package com.maspassword.app.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
import com.maspassword.app.App
import com.maspassword.app.R
import java.util.concurrent.atomic.AtomicInteger

/**
 * System autofill provider. Runs in the SAME process as the app, so it sees
 * the in-memory [com.maspassword.app.Session]:
 *
 *  - Locked (no keys in RAM — e.g. first use after boot/process death):
 *    one authenticated response, "Unlock MasPassword". Tapping it opens
 *    [AutofillAuthActivity] which asks for the master password, matches and
 *    returns the real datasets.
 *  - Unlocked + a browser-provided web domain with matches: one dataset per
 *    matching item, titled with the item name. Every dataset requires
 *    authentication (biometric / device credential confirm) before the
 *    values are released to the target app.
 *  - Unlocked, no domain or no matches (e.g. any native app): a single
 *    "Search MasPassword" authenticated entry — never an automatic
 *    suggestion. Matching is fail-closed in :core Domains, like the Chrome
 *    extension; app package names are deliberately NOT mapped to domains.
 *
 * Honest limitations (also in README): no SaveInfo (read-only client), so
 * the "save password?" bar never appears; nothing can be offered until the
 * first unlock after process start; browsers only get suggestions when they
 * report webDomain (Chrome autofill-framework compat mode).
 */
class MasPasswordAutofillService : AutofillService() {

    private val requestCounter = AtomicInteger(1000)

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val app = application as App
        val structure = request.fillContexts.lastOrNull()?.structure
            ?: return callback.onSuccess(null)

        // Never offer to fill our own windows.
        if (structure.activityComponent?.packageName == packageName) {
            return callback.onSuccess(null)
        }
        if (!app.store.isLinked) return callback.onSuccess(null)

        val parsed = ParsedStructure.parse(structure)
        if (!parsed.hasFields) return callback.onSuccess(null)

        if (!app.session.isUnlocked) {
            val response = FillResponse.Builder()
                .setAuthentication(
                    parsed.autofillIds,
                    authIntent(AutofillAuthActivity.MODE_UNLOCK, parsed, itemId = null),
                    presentation(getString(R.string.autofill_unlock_title), app.store.email.orEmpty()),
                )
                .build()
            return callback.onSuccess(response)
        }

        val matches = app.repo.matchesForDomain(parsed.webDomain)
        val builder = FillResponse.Builder()
        if (matches.isEmpty()) {
            // No verified domain match: manual pick only (still authenticated).
            builder.setAuthentication(
                parsed.autofillIds,
                authIntent(AutofillAuthActivity.MODE_PICK, parsed, itemId = null),
                presentation(getString(R.string.autofill_search_title), getString(R.string.autofill_search_subtitle)),
            )
        } else {
            for (match in matches.take(MAX_DATASETS)) {
                val pres = presentation(
                    match.data.title.ifBlank { getString(R.string.item_untitled) },
                    match.data.username,
                )
                val dataset = Dataset.Builder().apply {
                    // Values are withheld (null) until the per-dataset
                    // authentication below releases the real Dataset.
                    parsed.usernameId?.let { setValue(it, null, pres) }
                    parsed.passwordId?.let { setValue(it, null, pres) }
                    setAuthentication(
                        authIntent(AutofillAuthActivity.MODE_CONFIRM, parsed, match.itemId),
                    )
                }.build()
                builder.addDataset(dataset)
            }
        }
        callback.onSuccess(builder.build())
    }

    /** Read-only client: SaveInfo is never set, so this should never run. */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onFailure(getString(R.string.autofill_save_unsupported))
    }

    private fun authIntent(mode: String, parsed: ParsedStructure, itemId: String?): android.content.IntentSender {
        val intent = Intent(this, AutofillAuthActivity::class.java).apply {
            putExtra(AutofillAuthActivity.EXTRA_MODE, mode)
            putExtra(AutofillAuthActivity.EXTRA_USERNAME_ID, parsed.usernameId)
            putExtra(AutofillAuthActivity.EXTRA_PASSWORD_ID, parsed.passwordId)
            putExtra(AutofillAuthActivity.EXTRA_WEB_DOMAIN, parsed.webDomain)
            putExtra(AutofillAuthActivity.EXTRA_ITEM_ID, itemId)
        }
        // MUTABLE: the autofill framework attaches its client state extras to
        // the launched intent. Unique request codes keep intents distinct.
        val flags = PendingIntent.FLAG_CANCEL_CURRENT or
            (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        return PendingIntent.getActivity(this, requestCounter.incrementAndGet(), intent, flags)
            .intentSender
    }

    @Suppress("DEPRECATION") // RemoteViews presentations: valid on 26..34, replaced by Presentations on 33+.
    private fun presentation(title: String, subtitle: String): RemoteViews =
        RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.af_title, title)
            if (subtitle.isBlank()) {
                setViewVisibility(R.id.af_subtitle, android.view.View.GONE)
            } else {
                setTextViewText(R.id.af_subtitle, subtitle)
            }
        }

    private companion object {
        const val MAX_DATASETS = 5
    }
}
