package com.maspassword.app.ui

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.maspassword.app.App
import com.maspassword.app.Bg
import com.maspassword.app.R
import com.maspassword.app.net.ApiException

/**
 * Vault browser: every item of every vault (personal + shared), decrypted in
 * memory, with client-side search. Also hosts the biometric re-entry gate
 * ("app open" gate): armed in onStop, checked in onStart while keys are
 * still in RAM. Process death drops the keys, so the gate then naturally
 * falls back to the master password via RouterActivity/UnlockActivity.
 */
class HomeActivity : AppCompatActivity() {

    private lateinit var adapter: ItemAdapter
    private lateinit var progress: ProgressBar
    private lateinit var emptyText: TextView
    private lateinit var contentGroup: View
    private var gateShowing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)
        setSupportActionBar(findViewById<Toolbar>(R.id.home_toolbar))

        progress = findViewById(R.id.home_progress)
        emptyText = findViewById(R.id.home_empty)
        contentGroup = findViewById(R.id.home_content)

        adapter = ItemAdapter { item ->
            startActivity(
                Intent(this, ItemDetailActivity::class.java)
                    .putExtra(ItemDetailActivity.EXTRA_ITEM_ID, item.itemId),
            )
        }
        findViewById<RecyclerView>(R.id.home_list).apply {
            layoutManager = LinearLayoutManager(this@HomeActivity)
            adapter = this@HomeActivity.adapter
        }
        findViewById<EditText>(R.id.home_search).doAfterTextChanged {
            adapter.filter(it?.toString().orEmpty())
        }
    }

    override fun onStart() {
        super.onStart()
        val app = App.from(this)
        if (!app.session.isUnlocked) { // locked (or process restarted): password
            startActivity(Intent(this, RouterActivity::class.java))
            finish()
            return
        }
        if (app.store.biometricEnabled && app.session.biometricGateArmed &&
            BiometricGate.available(this) && !gateShowing
        ) {
            gateShowing = true
            contentGroup.visibility = View.INVISIBLE
            BiometricGate.prompt(
                this,
                getString(R.string.biometric_title),
                app.store.email,
            ) { ok ->
                gateShowing = false
                if (ok) {
                    app.session.biometricGateArmed = false
                    contentGroup.visibility = View.VISIBLE
                } else {
                    finishAffinity() // leave the app; keys stay only in RAM
                }
            }
        } else {
            contentGroup.visibility = View.VISIBLE
        }
        loadItems(force = false)
    }

    override fun onStop() {
        super.onStop()
        val app = App.from(this)
        if (app.store.biometricEnabled) app.session.biometricGateArmed = true
    }

    private fun loadItems(force: Boolean) {
        val app = App.from(this)
        progress.visibility = View.VISIBLE
        Bg.submit(work = { app.repo.loadAll(force) }) { result ->
            progress.visibility = View.GONE
            result.fold(
                onSuccess = { snapshot ->
                    adapter.submit(snapshot.items)
                    emptyText.visibility = if (snapshot.items.isEmpty()) View.VISIBLE else View.GONE
                    emptyText.text = getString(R.string.home_empty)
                },
                onFailure = { e ->
                    emptyText.visibility = View.VISIBLE
                    emptyText.text = e.message ?: getString(R.string.error_generic)
                    if (e is ApiException && e.isUnauthorized) {
                        // Token revoked server-side: lock and fall back.
                        app.session.lock()
                        startActivity(Intent(this, RouterActivity::class.java))
                        finish()
                    }
                },
            )
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_home, menu)
        menu.findItem(R.id.action_biometric).isChecked = App.from(this).store.biometricEnabled
        menu.findItem(R.id.action_biometric).isVisible = BiometricGate.available(this)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val app = App.from(this)
        return when (item.itemId) {
            R.id.action_refresh -> {
                loadItems(force = true); true
            }
            R.id.action_biometric -> {
                item.isChecked = !item.isChecked
                app.store.biometricEnabled = item.isChecked
                true
            }
            R.id.action_lock -> {
                app.session.lock()
                startActivity(Intent(this, UnlockActivity::class.java))
                finish()
                true
            }
            R.id.action_unlink -> {
                AlertDialog.Builder(this)
                    .setTitle(R.string.unlink_title)
                    .setMessage(R.string.unlink_message)
                    .setPositiveButton(R.string.unlink_confirm) { _, _ ->
                        app.session.lock()
                        app.store.clearLink()
                        startActivity(Intent(this, LinkActivity::class.java))
                        finish()
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}
