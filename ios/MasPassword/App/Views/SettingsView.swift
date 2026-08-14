import SwiftUI
import UIKit

struct SettingsView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var confirmUnlink = false

    var body: some View {
        NavigationStack {
            Form {
                if let account = appState.account {
                    Section("Linked account") {
                        LabeledContent("Server", value: account.serverUrl)
                        LabeledContent("Email", value: account.email)
                        if !account.displayName.isEmpty {
                            LabeledContent("Name", value: account.displayName)
                        }
                        LabeledContent("Linked", value: account.linkedAt.formatted(date: .abbreviated, time: .shortened))
                    }
                }

                Section {
                    Toggle("Require Face ID / Touch ID on return", isOn: Binding(
                        get: { appState.biometricGateEnabled },
                        set: { appState.biometricGateEnabled = $0 }
                    ))
                } footer: {
                    Text("Re-covers the app with a biometric check after it goes to the background. "
                         + "Biometrics only lift this curtain — they can never replace the master "
                         + "password: if the app process is killed, the password is required again "
                         + "because keys live only in memory.")
                }

                Section {
                    Button("Sync now") {
                        Task { await appState.sync() }
                    }
                    .disabled(appState.phase != .unlocked || appState.syncing)
                } footer: {
                    if let error = appState.lastSyncError {
                        Text(error).foregroundStyle(.red)
                    }
                }

                Section {
                    Button("Enable AutoFill…") {
                        // Deep-linking to the exact pane is not API-stable;
                        // opening the app's settings gets the user close.
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }
                } footer: {
                    Text("Then: Settings › Passwords › Password Options › enable MasPassword "
                         + "under “Allow filling from”.")
                }

                Section {
                    Button("Unlink this device", role: .destructive) {
                        confirmUnlink = true
                    }
                } footer: {
                    Text("Removes the device token, the encrypted cache and QuickType entries "
                         + "from this device. Also revoke the device in the web app "
                         + "(Settings › Devices).")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog("Unlink this device?", isPresented: $confirmUnlink, titleVisibility: .visible) {
                Button("Unlink", role: .destructive) {
                    Task {
                        await appState.unlink()
                        dismiss()
                    }
                }
            }
        }
    }
}
