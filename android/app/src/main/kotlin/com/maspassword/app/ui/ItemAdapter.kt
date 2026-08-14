package com.maspassword.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.maspassword.app.R
import com.maspassword.app.Session

/** Flat list of decrypted items with client-side search filtering. */
class ItemAdapter(
    private val onClick: (Session.DecryptedItem) -> Unit,
) : RecyclerView.Adapter<ItemAdapter.Holder>() {

    private var all: List<Session.DecryptedItem> = emptyList()
    private var shown: List<Session.DecryptedItem> = emptyList()
    private var query: String = ""

    fun submit(items: List<Session.DecryptedItem>) {
        all = items
        refilter()
    }

    fun filter(newQuery: String) {
        query = newQuery
        refilter()
    }

    private fun refilter() {
        shown = if (query.isBlank()) all else all.filter { it.data.matchesQuery(query) }
        notifyDataSetChanged()
    }

    override fun getItemCount() = shown.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.row_item, parent, false)
        return Holder(view)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(shown[position])

    inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
        private val initial: TextView = view.findViewById(R.id.row_initial)
        private val title: TextView = view.findViewById(R.id.row_title)
        private val subtitle: TextView = view.findViewById(R.id.row_subtitle)
        private val favorite: TextView = view.findViewById(R.id.row_favorite)

        fun bind(item: Session.DecryptedItem) {
            val d = item.data
            val name = d.title.ifBlank { itemView.context.getString(R.string.item_untitled) }
            initial.text = name.take(1).uppercase()
            title.text = name
            val sub = listOf(d.username, item.vaultName).filter { it.isNotBlank() }
            subtitle.text = sub.joinToString("  ·  ")
            subtitle.visibility = if (subtitle.text.isBlank()) View.GONE else View.VISIBLE
            favorite.visibility = if (d.favorite) View.VISIBLE else View.GONE
            itemView.setOnClickListener { onClick(item) }
        }
    }
}
