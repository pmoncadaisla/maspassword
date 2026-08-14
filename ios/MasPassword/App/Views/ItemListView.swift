import SwiftUI

/// Items of one vault, searchable across title/username/url/notes/tags
/// (ItemData.matchesQuery — the password is never searched).
struct ItemListView: View {
    @EnvironmentObject private var appState: AppState
    let vaultId: String
    @State private var query = ""

    private var items: [DecryptedItem] {
        let all = appState.session?.items(inVault: vaultId) ?? []
        guard !query.isEmpty else { return all }
        return all.filter { $0.data.matchesQuery(query) }
    }

    var body: some View {
        List(items) { item in
            NavigationLink {
                ItemDetailView(item: item)
            } label: {
                ItemRow(item: item)
            }
        }
        .searchable(text: $query, prompt: "Search title, user, url, tags")
        .navigationTitle(appState.session?.vaultName(vaultId) ?? "Items")
        .navigationBarTitleDisplayMode(.inline)
        .overlay {
            if items.isEmpty {
                ContentUnavailableCompat(
                    text: query.isEmpty ? "This vault is empty." : "No items match “\(query)”.")
            }
        }
        .refreshable { await appState.sync() }
    }
}

struct ItemRow: View {
    let item: DecryptedItem

    private var icon: String {
        switch item.data.type {
        case "card": return "creditcard"
        case "note": return "note.text"
        case "identity": return "person.text.rectangle"
        default: return "key.fill"
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(.tint)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(item.data.title.isEmpty ? "Untitled" : item.data.title)
                        .lineLimit(1)
                    if item.data.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(.yellow)
                    }
                }
                if !item.data.username.isEmpty {
                    Text(item.data.username)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
        }
    }
}

/// iOS 16-compatible stand-in for ContentUnavailableView (iOS 17+).
struct ContentUnavailableCompat: View {
    let text: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
    }
}
