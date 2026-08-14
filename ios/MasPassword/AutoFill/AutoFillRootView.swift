import SwiftUI

/// SwiftUI face of the AutoFill extension.
struct AutoFillRootView: View {
    @ObservedObject var model: AutoFillModel
    @State private var masterPassword = ""
    @State private var query = ""

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("MasPassword")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { model.cancel() }
                    }
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .notLinked:
            VStack(spacing: 12) {
                Image(systemName: "iphone.slash").font(.largeTitle).foregroundStyle(.secondary)
                Text("No linked vault").font(.headline)
                Text("Open the MasPassword app and link this device with the QR code "
                     + "from the web vault, then unlock it once.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
        case .configurationInfo:
            VStack(spacing: 12) {
                Image(systemName: "checkmark.seal").font(.largeTitle).foregroundStyle(.green)
                Text("MasPassword is ready").font(.headline)
                Text("Suggestions appear above the keyboard after you unlock and sync "
                     + "the app. Each fill asks for your master password — keys are "
                     + "never stored on this device.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                Button("Done") { model.cancel() }.buttonStyle(.borderedProminent)
            }
        case .locked:
            unlockForm
        case .unlocked:
            itemList
        }
    }

    private var unlockForm: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "lock.shield").font(.system(size: 44)).foregroundStyle(.tint)
            Text(model.accountEmail).font(.subheadline).foregroundStyle(.secondary)
            SecureField("Master password", text: $masterPassword)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .submitLabel(.go)
                .onSubmit { model.unlock(masterPassword: masterPassword) }
                .padding(.horizontal, 28)
            Button {
                model.unlock(masterPassword: masterPassword)
            } label: {
                if model.working {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("Unlock").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(masterPassword.isEmpty || model.working)
            .padding(.horizontal, 28)

            if let error = model.errorMessage {
                Text(error).font(.footnote).foregroundStyle(.red)
                    .multilineTextAlignment(.center).padding(.horizontal)
            }
            Text("Your master password never leaves this device and is asked on every fill.")
                .font(.caption2).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).padding(.horizontal, 36)
            Spacer()
        }
    }

    private var itemList: some View {
        List {
            if !model.matchingItems.isEmpty {
                Section("For this site") {
                    ForEach(model.matchingItems) { item in
                        row(item)
                    }
                }
            } else {
                Section {
                    Text("No saved login matches this site — matching is by exact "
                         + "registrable domain to prevent phishing.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            Section(model.matchingItems.isEmpty ? "All logins" : "Other logins") {
                ForEach(model.filteredOthers(query: query)) { item in
                    row(item)
                }
            }
        }
        .searchable(text: $query, prompt: "Search other logins")
    }

    private func row(_ item: DecryptedItem) -> some View {
        Button {
            model.provide(item)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.data.title.isEmpty ? "Untitled" : item.data.title)
                    .foregroundStyle(.primary)
                HStack(spacing: 6) {
                    if !item.data.username.isEmpty {
                        Text(item.data.username)
                    }
                    if !item.data.url.isEmpty {
                        Text(item.data.url).lineLimit(1)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
    }
}
