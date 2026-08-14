package com.maspassword.app.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * Deterministic single-pass parse of an autofill [AssistStructure]:
 * find the username and password fields and the page's web domain.
 *
 * Selection order (first match wins):
 *  1. Explicit autofill hints (`android:autofillHints`, or the browser's
 *     mapping of `autocomplete=`): "password" / "username" / "emailAddress".
 *  2. HTML attributes in compat mode: `<input type="password">`.
 *  3. Input types: textPassword / textWebPassword / numberPassword.
 *  4. Name heuristics on idEntry/hint (pass|pwd|contraseña; user|email|
 *     login|correo|usuario|mail).
 *  5. For the username only: the last plain text field seen BEFORE the
 *     password field (the classic login-form shape).
 *
 * The web domain is taken from `ViewNode.webDomain` — the OS/browser-provided
 * value, never text scraped from the page. If no node carries one (a native
 * app), [webDomain] stays null and the caller MUST NOT auto-suggest.
 */
class ParsedStructure private constructor(
    val usernameId: AutofillId?,
    val passwordId: AutofillId?,
    val webDomain: String?,
) {
    val hasFields: Boolean get() = usernameId != null || passwordId != null

    /** Ids the fill response should be associated with. */
    val autofillIds: Array<AutofillId>
        get() = listOfNotNull(usernameId, passwordId).toTypedArray()

    companion object {
        private val PASSWORD_NAME_RE = Regex("pass|pwd|contrase", RegexOption.IGNORE_CASE)
        private val USERNAME_NAME_RE = Regex("user|email|login|correo|usuario|mail|account", RegexOption.IGNORE_CASE)

        private class Candidate(
            val id: AutofillId,
            val isPasswordType: Boolean,
            val hintsPassword: Boolean,
            val hintsUsername: Boolean,
            val namePassword: Boolean,
            val nameUsername: Boolean,
        )

        fun parse(structure: AssistStructure): ParsedStructure {
            val fields = ArrayList<Candidate>()
            var webDomain: String? = null

            fun visit(node: AssistStructure.ViewNode) {
                if (webDomain == null) {
                    node.webDomain?.takeIf { it.isNotBlank() }?.let { webDomain = it }
                }
                if (node.autofillId != null && node.autofillType == View.AUTOFILL_TYPE_TEXT &&
                    node.visibility == View.VISIBLE
                ) {
                    val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
                    val names = "${node.idEntry.orEmpty()} ${node.hint.orEmpty()}"
                    val htmlType = node.htmlInfo?.attributes
                        ?.firstOrNull { it.first.equals("type", ignoreCase = true) }?.second
                    fields.add(
                        Candidate(
                            id = node.autofillId!!,
                            isPasswordType = isPasswordInputType(node.inputType) ||
                                "password".equals(htmlType, ignoreCase = true),
                            hintsPassword = View.AUTOFILL_HINT_PASSWORD in hints,
                            hintsUsername = View.AUTOFILL_HINT_USERNAME in hints ||
                                View.AUTOFILL_HINT_EMAIL_ADDRESS in hints,
                            namePassword = PASSWORD_NAME_RE.containsMatchIn(names),
                            nameUsername = USERNAME_NAME_RE.containsMatchIn(names),
                        ),
                    )
                }
                for (i in 0 until node.childCount) visit(node.getChildAt(i))
            }
            for (i in 0 until structure.windowNodeCount) {
                visit(structure.getWindowNodeAt(i).rootViewNode)
            }

            val password = fields.firstOrNull { it.hintsPassword }
                ?: fields.firstOrNull { it.isPasswordType }
                ?: fields.firstOrNull { it.namePassword }

            val username = fields.firstOrNull { it.hintsUsername }
                ?: password?.let { pw ->
                    // Last non-password text field before the password field.
                    fields.takeWhile { it !== pw }.lastOrNull { !it.isPasswordType && !it.namePassword }
                }
                ?: fields.firstOrNull { it.nameUsername && !it.isPasswordType }

            return ParsedStructure(
                usernameId = username?.id.takeIf { it != password?.id },
                passwordId = password?.id,
                webDomain = webDomain,
            )
        }

        private fun isPasswordInputType(inputType: Int): Boolean {
            val clazz = inputType and InputType.TYPE_MASK_CLASS
            val variation = inputType and InputType.TYPE_MASK_VARIATION
            return when (clazz) {
                InputType.TYPE_CLASS_TEXT ->
                    variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                        variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
                InputType.TYPE_CLASS_NUMBER ->
                    variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
                else -> false
            }
        }
    }
}
