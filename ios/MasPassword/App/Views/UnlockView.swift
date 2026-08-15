import SwiftUI

/// Master-password prompt for a linked device. Works fully offline against
/// the encrypted cache; a fresh sync runs in the background after unlock.
struct UnlockView: View {
    @EnvironmentObject private var appState: AppState

    @State private var masterPassword = ""
    @State private var working = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: "lock.shield")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                if let account = appState.account {
                    VStack(spacing: 4) {
                        Text(account.email).font(.headline)
                        Text(account.serverUrl).font(.footnote).foregroundStyle(.secondary)
                    }
                }

                SecureField("Master password", text: $masterPassword)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .submitLabel(.go)
                    .onSubmit { Task { await unlock() } }
                    .padding(.horizontal, 32)

                Button {
                    Task { await unlock() }
                } label: {
                    if working {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("Unlock").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(masterPassword.isEmpty || working)
                .padding(.horizontal, 32)

                if let errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

                Text("Your master password is required after every app restart — "
                     + "it is never stored on this device.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 40)

                Spacer()
                Button("Unlink this device", role: .destructive) {
                    Task { await appState.unlink() }
                }
                .font(.footnote)
                .padding(.bottom)
            }
            .navigationTitle("Sésamo")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func unlock() async {
        guard !masterPassword.isEmpty else { return }
        working = true
        defer { working = false }
        do {
            try await appState.unlock(masterPassword: masterPassword)
            masterPassword = ""
            errorMessage = nil
        } catch VaultUnlocker.UnlockError.wrongMasterPassword {
            errorMessage = "Wrong master password."
        } catch VaultUnlocker.UnlockError.noCache {
            errorMessage = "No local vault cache found — unlink and pair again."
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? "\(error)"
        }
    }
}
