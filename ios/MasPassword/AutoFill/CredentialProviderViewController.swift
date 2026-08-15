import AuthenticationServices
import UIKit
import SwiftUI
import MasPasswordCore

/// The AutoFill Credential Provider (declared via NSExtension attributes in
/// project.yml: extension point com.apple.authentication-services-credential-provider-ui).
///
/// Zero-knowledge consequences, stated plainly:
///
///  - The extension process NEVER has a persisted key. Every invocation that
///    must return a password requires the user to type the master password
///    (the derived key exists only in this short-lived process's RAM).
///  - `provideCredentialWithoutUserInteraction` therefore ALWAYS fails with
///    `.userInteractionRequired` — iOS then calls
///    `prepareInterfaceToProvideCredential`, where we show the unlock UI.
///  - What the extension CAN read without the master password: the linked
///    account (shared keychain) and the encrypted cache (App Group file) —
///    both ciphertext/metadata only.
struct AutoFillRequest {
    /// Domains/URLs of the app or page being filled, mapped to core types.
    var serviceIdentifiers: [(value: String, kind: Domains.ServiceIdentifierKind)] = []
    /// The item id when arriving from a QuickType suggestion.
    var recordIdentifier: String?
}

final class CredentialProviderViewController: ASCredentialProviderViewController {

    private let model = AutoFillModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        model.onProvide = { [weak self] username, password in
            self?.extensionContext.completeRequest(
                withSelectedCredential: ASPasswordCredential(user: username, password: password),
                completionHandler: nil)
        }
        model.onCancel = { [weak self] in
            self?.extensionContext.cancelRequest(
                withError: NSError(domain: ASExtensionErrorDomain,
                                   code: ASExtensionError.userCanceled.rawValue))
        }

        let host = UIHostingController(rootView: AutoFillRootView(model: model))
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        host.didMove(toParent: self)
    }

    /// User picked Sésamo from the AutoFill picker: show the list
    /// filtered by the page's service identifiers (after unlock).
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.begin(request: AutoFillRequest(
            serviceIdentifiers: serviceIdentifiers.map { ($0.identifier, $0.kind) },
            recordIdentifier: nil))
    }

    /// QuickType tap, fast path. The derived key only ever lives in RAM and
    /// this process has none -> ALWAYS demand interaction (fail closed).
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain,
                               code: ASExtensionError.userInteractionRequired.rawValue))
    }

    /// QuickType tap, interactive path: unlock, then complete with the exact
    /// item the identity's recordIdentifier points at.
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        var request = AutoFillRequest()
        request.recordIdentifier = credentialIdentity.recordIdentifier
        request.serviceIdentifiers = [(credentialIdentity.serviceIdentifier.identifier,
                                       credentialIdentity.serviceIdentifier.kind)]
        model.begin(request: request)
    }

    /// "Set up Sésamo in Settings > Passwords": nothing to configure
    /// beyond having linked the app, so just explain and close.
    override func prepareInterfaceForExtensionConfiguration() {
        model.beginConfigurationInfo()
    }
}

private extension ASCredentialServiceIdentifier {
    var kind: Domains.ServiceIdentifierKind {
        switch type {
        case .URL: return .url
        default: return .domain
        }
    }
}
