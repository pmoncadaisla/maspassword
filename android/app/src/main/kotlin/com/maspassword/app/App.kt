package com.maspassword.app

import android.app.Application
import android.content.Context
import com.maspassword.app.net.VaultRepository

/**
 * Process-wide wiring. The [Session] (and with it every decryption key) lives
 * here in plain process memory: when Android kills the process, the keys are
 * gone and the next launch asks for the master password again — that is the
 * zero-knowledge model working as intended, not a bug.
 */
class App : Application() {

    val store: SecureStore by lazy { SecureStore(this) }
    val session: Session = Session()
    val repo: VaultRepository by lazy { VaultRepository(store, session) }

    companion object {
        fun from(context: Context): App = context.applicationContext as App
    }
}
