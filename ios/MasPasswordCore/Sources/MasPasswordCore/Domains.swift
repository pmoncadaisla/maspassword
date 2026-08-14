import Foundation

/// Registrable-domain (eTLD+1) matching, ported from `extension/domain.js`
/// (and aligned with the Android port in `android/core .../Domains.kt`).
///
/// Anti-phishing invariant (same as the Chrome extension): a saved login is
/// offered for a page ONLY when both sides reduce to the same registrable
/// domain. Never substring comparison. Any unparseable or empty input matches
/// nothing (fail closed). `evil-google.com`, `paypal.com.attacker.com` and
/// `google.evil.com` do NOT match `google.com` / `paypal.com`.
///
/// One deliberate divergence, item-side only (same as Android): saved item
/// URLs without a scheme ("example.com/login") are retried as https:// before
/// giving up, because the SAVED url is user data, not attacker-controlled
/// input — the page side (AutoFill service identifier) stays strict.
public enum Domains {

    /// The AutoFill extension receives service identifiers typed either as a
    /// bare domain or a full URL (`ASCredentialServiceIdentifier.IdentifierType`).
    /// Mirrored here as a plain enum so this module never imports
    /// AuthenticationServices and stays testable everywhere.
    public enum ServiceIdentifierKind: Sendable {
        case domain
        case url
    }

    // Same embedded set as extension/domain.js. Not exhaustive: covers common
    // multi-part public suffixes; everything else uses the last-two-labels rule.
    private static let multiPartSuffixes: Set<String> = [
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "co.jp",
        "co.kr",
        "com.au", "net.au", "org.au",
        "com.br",
        "com.mx",
        "co.nz",
        "co.za",
        "com.sg",
        "com.tr",
    ]

    /// Bare IP literal (v4, or v6 with/without brackets)?
    public static func isIpAddress(_ host: String) -> Bool {
        if isIpv4(host) { return true }
        if host.hasPrefix("[") && host.hasSuffix("]") { return true }
        if host.contains(":") { return true }
        return false
    }

    private static func isIpv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        for part in parts {
            guard (1...3).contains(part.count), part.allSatisfy({ $0.isASCII && $0.isNumber }) else {
                return false
            }
        }
        return true
    }

    /// Reduce a hostname to its registrable domain (eTLD+1). Lowercases,
    /// strips a trailing dot and a single leading "www.". IPs / localhost /
    /// single-label hosts are returned unchanged. Empty input -> "".
    public static func registrableDomain(_ hostname: String?) -> String {
        guard let hostname, !hostname.isEmpty else { return "" }
        var host = hostname.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasSuffix(".") { host.removeLast() }          // strip FQDN trailing dot
        if host.hasPrefix("www.") { host.removeFirst(4) }     // strip a single leading www.
        if host.isEmpty { return "" }

        if host == "localhost" { return host }
        if isIpAddress(host) { return host }

        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if labels.count <= 2 { return host }

        let lastTwo = labels.suffix(2).joined(separator: ".")
        if multiPartSuffixes.contains(lastTwo) {
            // Public suffix is two labels (e.g. co.uk) -> eTLD+1 is 3 labels.
            return labels.suffix(3).joined(separator: ".")
        }
        // Generic case: the public suffix is one label -> eTLD+1 is 2 labels.
        return lastTwo
    }

    /// Hostname of an absolute URL, or "" when unparseable (fail closed).
    /// Mirrors JS `new URL(url).hostname`: scheme-less input yields "".
    /// IPv6 hosts come back WITHOUT brackets ("::1"), which `isIpAddress`
    /// still classifies as an IP via the ':' check.
    public static func hostnameOf(_ url: String?) -> String {
        guard let url, !url.trimmingCharacters(in: .whitespaces).isEmpty else { return "" }
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme != nil,
              let host = components.host, !host.isEmpty else { return "" }
        return host
    }

    /// Hostname of a SAVED item URL. First tries the strict parse; if that
    /// yields nothing and the value has no scheme, retries with "https://".
    public static func hostnameOfItemUrl(_ itemUrl: String?) -> String {
        guard let itemUrl, !itemUrl.trimmingCharacters(in: .whitespaces).isEmpty else { return "" }
        let strict = hostnameOf(itemUrl)
        if !strict.isEmpty { return strict }
        let trimmed = itemUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("://") { return "" } // had a scheme and still failed
        return hostnameOf("https://" + trimmed)
    }

    /// True iff both URLs parse AND share a registrable domain (fail closed).
    /// Byte-for-byte port of `domainsMatch` in extension/domain.js.
    public static func domainsMatch(_ urlA: String?, _ urlB: String?) -> Bool {
        let hostA = hostnameOf(urlA)
        let hostB = hostnameOf(urlB)
        if hostA.isEmpty || hostB.isEmpty { return false }
        let regA = registrableDomain(hostA)
        let regB = registrableDomain(hostB)
        if regA.isEmpty || regB.isEmpty { return false }
        return regA == regB
    }

    /// AutoFill matching: does a saved item's URL match the service identifier
    /// iOS reports for the app/page being filled?
    ///
    ///  - `.domain` identifiers are bare hostnames ("app.example.co.uk");
    ///    identifiers containing separators/spaces are rejected (fail closed).
    ///  - `.url` identifiers go through the strict URL path.
    ///  - The item side uses the lenient `hostnameOfItemUrl` (https:// retry).
    public static func matches(serviceIdentifier: String, kind: ServiceIdentifierKind, itemUrl: String?) -> Bool {
        let itemHost = hostnameOfItemUrl(itemUrl)
        if itemHost.isEmpty { return false }
        let regItem = registrableDomain(itemHost)
        if regItem.isEmpty { return false }

        let pageHost: String
        switch kind {
        case .domain:
            let host = serviceIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if host.isEmpty { return false }
            if host.contains(where: { $0 == "/" || $0 == "\\" || $0 == "@" || $0.isWhitespace }) { return false }
            pageHost = host
        case .url:
            pageHost = hostnameOf(serviceIdentifier)
            if pageHost.isEmpty { return false }
        }

        let regPage = registrableDomain(pageHost)
        if regPage.isEmpty { return false }
        return regPage == regItem
    }

    /// The domain to register in the system QuickType credential-identity
    /// store for a saved item, or nil when the item has no usable URL.
    /// Uses the registrable domain so iOS suggests the login on any
    /// subdomain of the site, matching the extension's eTLD+1 semantics.
    public static func identityDomain(forItemUrl itemUrl: String?) -> String? {
        let host = hostnameOfItemUrl(itemUrl)
        if host.isEmpty { return nil }
        let reg = registrableDomain(host)
        return reg.isEmpty ? nil : reg
    }
}
