package com.maspassword.app.ui

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.maspassword.app.App

/**
 * Launcher with no UI of its own: routes to Link (not linked yet),
 * Unlock (linked but keys not in memory) or Home (unlocked).
 */
class RouterActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = App.from(this)
        val target = when {
            !app.store.isLinked -> LinkActivity::class.java
            !app.session.isUnlocked -> UnlockActivity::class.java
            else -> HomeActivity::class.java
        }
        startActivity(Intent(this, target))
        finish()
    }
}
