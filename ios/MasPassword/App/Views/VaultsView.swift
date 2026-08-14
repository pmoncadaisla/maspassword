import SwiftUI

/// Vault list — the unlocked home screen.
struct VaultsView: View {
    @EnvironmentObject private var appState: AppState
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            List {
                if let error = appState.lastSyncError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.orange)
                    }
                }
                Section {
                    ForEach(appState.session?.vaults ?? []) { vault in
                        NavigationLink(value: vault.id) {
                            HStack {
                                Image(systemName: vault.isShared ? "person.2.fill" : "lock.fill")
                                    .foregroundStyle(.tint)
                                    .frame(width: 28)
                                VStack(alignment: .leading) {
                                    Text(vault.name.isEmpty ? "Vault" : vault.name)
                                    Text("\(appState.session?.items(inVault: vault.id).count ?? 0) items"
                                         + (vault.isShared ? " · shared" : ""))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                } footer: {
                    if appState.session?.vaults.isEmpty == true {
                        Text("No vaults could be decrypted. Pull to refresh after checking the account in the web app.")
                    }
                }
            }
            .navigationTitle("Vaults")
            .navigationDestination(for: String.self) { vaultId in
                ItemListView(vaultId: vaultId)
            }
            .refreshable { await appState.sync() }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    HStack {
                        if appState.syncing { ProgressView() }
                        Button {
                            appState.lock()
                        } label: {
                            Image(systemName: "lock")
                        }
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
        }
    }
}
