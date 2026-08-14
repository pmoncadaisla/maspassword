import SwiftUI
import UIKit
import MasPasswordCore

/// Item detail: copy (with clipboard auto-expiration), reveal password,
/// live TOTP with countdown, custom fields, notes, tags.
struct ItemDetailView: View {
    let item: DecryptedItem

    @State private var passwordRevealed = false
    @State private var copiedField: String?

    var body: some View {
        List {
            if !item.data.username.isEmpty {
                copyRow(label: "Username", value: item.data.username, id: "username", monospaced: false)
            }

            if !item.data.password.isEmpty {
                Section {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Password").font(.caption).foregroundStyle(.secondary)
                            Text(passwordRevealed ? item.data.password : String(repeating: "•", count: 10))
                                .font(.body.monospaced())
                                .textSelection(.enabled)
                                .lineLimit(1)
                        }
                        Spacer()
                        Button {
                            passwordRevealed.toggle()
                        } label: {
                            Image(systemName: passwordRevealed ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        copyButton(value: item.data.password, id: "password")
                    }
                }
            }

            if !item.data.totpSecret.isEmpty {
                Section("One-time code") {
                    TotpRow(secret: item.data.totpSecret) { code in
                        copy(code, id: "totp")
                    }
                }
            }

            if !item.data.url.isEmpty {
                Section("Website") {
                    HStack {
                        Text(item.data.url).lineLimit(2).textSelection(.enabled)
                        Spacer()
                        copyButton(value: item.data.url, id: "url")
                    }
                }
            }

            ForEach(Array(item.data.customFields.enumerated()), id: \.offset) { index, field in
                Section(field.label.isEmpty ? "Field" : field.label) {
                    HStack {
                        Text(field.hidden ? String(repeating: "•", count: 6) : field.value)
                            .font(.body.monospaced())
                            .lineLimit(1)
                        Spacer()
                        copyButton(value: field.value, id: "cf-\(index)")
                    }
                }
            }

            if !item.data.notes.isEmpty {
                Section("Notes") {
                    Text(item.data.notes).textSelection(.enabled)
                }
            }

            if !item.data.tags.isEmpty {
                Section("Tags") {
                    Text(item.data.tags.joined(separator: " · "))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            if !item.data.attachments.isEmpty {
                Section("Attachments") {
                    ForEach(Array(item.data.attachments.enumerated()), id: \.offset) { _, attachment in
                        Label("\(attachment.name) (\(attachment.size) B)", systemImage: "paperclip")
                            .font(.footnote)
                    }
                }
            }
        }
        .navigationTitle(item.data.title.isEmpty ? "Item" : item.data.title)
        .navigationBarTitleDisplayMode(.inline)
        .overlay(alignment: .bottom) {
            if let copiedField {
                Text("\(copiedField) copied — clipboard clears in \(Int(MPConstants.clipboardTtlSeconds)) s")
                    .font(.caption)
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(.thinMaterial, in: Capsule())
                    .padding(.bottom, 12)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.default, value: copiedField)
    }

    // MARK: rows & helpers

    private func copyRow(label: String, value: String, id: String, monospaced: Bool) -> some View {
        Section {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(label).font(.caption).foregroundStyle(.secondary)
                    Text(value)
                        .font(monospaced ? .body.monospaced() : .body)
                        .textSelection(.enabled)
                        .lineLimit(1)
                }
                Spacer()
                copyButton(value: value, id: id)
            }
        }
    }

    private func copyButton(value: String, id: String) -> some View {
        Button {
            copy(value, id: id)
        } label: {
            Image(systemName: copiedField == id ? "checkmark" : "doc.on.doc")
        }
        .buttonStyle(.borderless)
    }

    private func copy(_ value: String, id: String) {
        Pasteboard.copyExpiring(value)
        copiedField = id
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if copiedField == id { copiedField = nil }
        }
    }
}

/// Local-only clipboard writes that self-destruct after the TTL, so secrets
/// don't linger (and never reach Universal Clipboard / Handoff).
enum Pasteboard {
    static func copyExpiring(_ value: String) {
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(MPConstants.clipboardTtlSeconds),
            ]
        )
    }
}

/// Live RFC 6238 code with a countdown ring, recomputed every second.
struct TotpRow: View {
    let secret: String
    let onCopy: (String) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { timeline in
            let now = Int64(timeline.date.timeIntervalSince1970)
            if let code = try? Totp.generate(secret: secret, unixSeconds: now) {
                HStack(spacing: 14) {
                    Text(formatted(code.code))
                        .font(.title2.monospaced().weight(.semibold))
                        .contentTransitionCompat()
                    Spacer()
                    ZStack {
                        Circle()
                            .stroke(.quaternary, lineWidth: 3)
                        Circle()
                            .trim(from: 0, to: CGFloat(code.remainingSeconds) / CGFloat(Totp.defaultPeriodSeconds))
                            .stroke(code.remainingSeconds <= 5 ? Color.red : Color.accentColor,
                                    style: StrokeStyle(lineWidth: 3, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(code.remainingSeconds)")
                            .font(.caption2.monospacedDigit())
                    }
                    .frame(width: 32, height: 32)
                    Button {
                        onCopy(code.code)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                }
            } else {
                Label("Invalid TOTP secret", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .font(.footnote)
            }
        }
    }

    private func formatted(_ code: String) -> String {
        guard code.count == 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: 3)
        return "\(code[..<mid]) \(code[mid...])"
    }
}

private extension View {
    /// `.contentTransition(.numericText())` needs iOS 17; no-op on 16.
    @ViewBuilder func contentTransitionCompat() -> some View {
        if #available(iOS 17.0, *) {
            self.contentTransition(.numericText())
        } else {
            self
        }
    }
}
