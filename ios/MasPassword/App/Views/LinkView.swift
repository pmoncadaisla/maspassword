import SwiftUI
import MasPasswordCore

/// Device pairing wizard.
///
/// Step 1 — obtain the payload: scan the QR the web app shows under
///          Settings > Devices (or paste the code manually).
/// Step 2 — enter the master password ONCE. It is used in-RAM to derive the
///          key and verify it by decrypting encrypted_private_key; only the
///          server/email/token triple is persisted (shared keychain).
struct LinkView: View {
    @EnvironmentObject private var appState: AppState

    @State private var payload: LinkPayload?
    @State private var pasted = ""
    @State private var masterPassword = ""
    @State private var working = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if let payload {
                    passwordStep(payload)
                } else {
                    scanStep
                }
            }
            .navigationTitle("Link device")
        }
    }

    // MARK: step 1 — scan / paste

    private var scanStep: some View {
        VStack(spacing: 16) {
            QRScannerView { code in
                handleCandidate(code)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 320)
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(.quaternary))
            .padding(.horizontal)

            Text("Scan the QR from the web app\n(Settings › Devices › Link device)")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            HStack {
                TextField("…or paste the pairing code", text: $pasted)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Use") { handleCandidate(pasted) }
                    .buttonStyle(.borderedProminent)
                    .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal)

            if let errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
            Spacer()
        }
        .padding(.top)
    }

    private func handleCandidate(_ raw: String) {
        do {
            let parsed = try QrPayload.parse(raw)
            errorMessage = nil
            payload = parsed
        } catch {
            errorMessage = "\(error)"
        }
    }

    // MARK: step 2 — master password

    private func passwordStep(_ payload: LinkPayload) -> some View {
        Form {
            Section("Server") {
                LabeledContent("URL", value: payload.serverUrl)
                LabeledContent("Account", value: payload.email)
            }
            Section {
                SecureField("Master password", text: $masterPassword)
                    .textInputAutocapitalization(.never)
            } footer: {
                Text("Verified locally by decrypting your key blob — the master password "
                     + "never leaves this device and is never stored. You will need to type "
                     + "it again whenever the app restarts.")
            }
            Section {
                Button {
                    Task { await link(payload) }
                } label: {
                    if working {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("Verify & link").frame(maxWidth: .infinity)
                    }
                }
                .disabled(masterPassword.isEmpty || working)

                Button("Scan a different code", role: .cancel) {
                    self.payload = nil
                    masterPassword = ""
                    errorMessage = nil
                }
                .disabled(working)
            }
            if let errorMessage {
                Section {
                    Text(errorMessage).foregroundStyle(.red).font(.footnote)
                }
            }
        }
    }

    private func link(_ payload: LinkPayload) async {
        working = true
        defer { working = false }
        do {
            try await appState.link(payload: payload, masterPassword: masterPassword)
            masterPassword = ""
        } catch VaultUnlocker.UnlockError.wrongMasterPassword {
            errorMessage = "Wrong master password (the key blob failed to decrypt)."
        } catch VaultUnlocker.UnlockError.encryptionNotSetUp {
            errorMessage = "This account has not finished encryption setup — open the web vault once first."
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? "\(error)"
        }
    }
}
