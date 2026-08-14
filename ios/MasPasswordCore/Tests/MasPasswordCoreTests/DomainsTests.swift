import XCTest
@testable import MasPasswordCore

/// Port of the extension's domain-matching expectations (extension/domain.js,
/// mirrored by android/core DomainsTest): eTLD+1 semantics, fail-closed
/// everywhere, anti-phishing negatives.
final class DomainsTests: XCTestCase {

    func testRegistrableDomain() {
        XCTAssertEqual(Domains.registrableDomain("google.com"), "google.com")
        XCTAssertEqual(Domains.registrableDomain("accounts.google.com"), "google.com")
        XCTAssertEqual(Domains.registrableDomain("deep.sub.accounts.google.com"), "google.com")
        XCTAssertEqual(Domains.registrableDomain("www.google.com"), "google.com")
        XCTAssertEqual(Domains.registrableDomain("GOOGLE.COM."), "google.com")

        // Multi-part public suffixes -> eTLD+1 keeps three labels.
        XCTAssertEqual(Domains.registrableDomain("app.example.co.uk"), "example.co.uk")
        XCTAssertEqual(Domains.registrableDomain("example.co.uk"), "example.co.uk")
        XCTAssertEqual(Domains.registrableDomain("a.b.example.com.au"), "example.com.au")

        // IPs, localhost and single labels pass through unchanged.
        XCTAssertEqual(Domains.registrableDomain("localhost"), "localhost")
        XCTAssertEqual(Domains.registrableDomain("127.0.0.1"), "127.0.0.1")
        XCTAssertEqual(Domains.registrableDomain("[::1]"), "[::1]")
        XCTAssertEqual(Domains.registrableDomain("::1"), "::1")
        XCTAssertEqual(Domains.registrableDomain("intranet"), "intranet")

        XCTAssertEqual(Domains.registrableDomain(""), "")
        XCTAssertEqual(Domains.registrableDomain(nil), "")
        // Mirrors the web exactly: the trailing dot is stripped FIRST, so
        // "www." becomes the single label "www" (not empty).
        XCTAssertEqual(Domains.registrableDomain("www."), "www")
        XCTAssertEqual(Domains.registrableDomain("www.example.com."), "example.com")
    }

    func testDomainsMatchPositive() {
        XCTAssertTrue(Domains.domainsMatch("https://accounts.google.com/signin", "https://www.google.com/"))
        XCTAssertTrue(Domains.domainsMatch("https://app.example.co.uk/login", "https://example.co.uk"))
        XCTAssertTrue(Domains.domainsMatch("http://localhost:3000/x", "http://localhost:8080"))
        XCTAssertTrue(Domains.domainsMatch("http://127.0.0.1:3000", "http://127.0.0.1"))
    }

    func testDomainsMatchAntiPhishingNegatives() {
        XCTAssertFalse(Domains.domainsMatch("https://evil-google.com", "https://google.com"))
        XCTAssertFalse(Domains.domainsMatch("https://paypal.com.attacker.com", "https://paypal.com"))
        XCTAssertFalse(Domains.domainsMatch("https://google.evil.com", "https://google.com"))
        XCTAssertFalse(Domains.domainsMatch("https://example.co.uk", "https://example.org.uk"))
    }

    func testDomainsMatchFailsClosed() {
        XCTAssertFalse(Domains.domainsMatch("", "https://google.com"))
        XCTAssertFalse(Domains.domainsMatch(nil, "https://google.com"))
        XCTAssertFalse(Domains.domainsMatch("not a url", "https://google.com"))
        // Strict side: scheme-less input does NOT parse (same as JS new URL()).
        XCTAssertFalse(Domains.domainsMatch("google.com", "https://google.com"))
        XCTAssertFalse(Domains.domainsMatch("javascript:alert(1)", "https://google.com"))
    }

    func testHostnameOfItemUrlLeniency() {
        // Saved item urls without a scheme get the https:// retry.
        XCTAssertEqual(Domains.hostnameOfItemUrl("example.com/login"), "example.com")
        XCTAssertEqual(Domains.hostnameOfItemUrl("www.example.co.uk"), "www.example.co.uk")
        XCTAssertEqual(Domains.hostnameOfItemUrl("https://x.example.com/a?b=c"), "x.example.com")
        // A scheme that still fails to parse is NOT retried.
        XCTAssertEqual(Domains.hostnameOfItemUrl("http://"), "")
        XCTAssertEqual(Domains.hostnameOfItemUrl(""), "")
        XCTAssertEqual(Domains.hostnameOfItemUrl(nil), "")
    }

    func testServiceIdentifierMatching() {
        // .domain identifiers are bare hostnames, as AutoFill reports them.
        XCTAssertTrue(Domains.matches(serviceIdentifier: "accounts.google.com", kind: .domain,
                                      itemUrl: "https://google.com/x"))
        XCTAssertTrue(Domains.matches(serviceIdentifier: "www.example.co.uk", kind: .domain,
                                      itemUrl: "app.example.co.uk/login")) // lenient item side
        XCTAssertFalse(Domains.matches(serviceIdentifier: "evil-google.com", kind: .domain,
                                       itemUrl: "https://google.com"))
        XCTAssertFalse(Domains.matches(serviceIdentifier: "google.com/phish", kind: .domain,
                                       itemUrl: "https://google.com")) // separators rejected
        XCTAssertFalse(Domains.matches(serviceIdentifier: "", kind: .domain, itemUrl: "https://google.com"))
        XCTAssertFalse(Domains.matches(serviceIdentifier: "accounts.google.com", kind: .domain, itemUrl: ""))
        XCTAssertFalse(Domains.matches(serviceIdentifier: "accounts.google.com", kind: .domain, itemUrl: nil))

        // .url identifiers use the strict URL path.
        XCTAssertTrue(Domains.matches(serviceIdentifier: "https://accounts.google.com/signin", kind: .url,
                                      itemUrl: "google.com"))
        XCTAssertFalse(Domains.matches(serviceIdentifier: "accounts.google.com", kind: .url,
                                       itemUrl: "https://google.com")) // bare host is not a URL
        XCTAssertFalse(Domains.matches(serviceIdentifier: "https://paypal.com.attacker.com", kind: .url,
                                       itemUrl: "https://paypal.com"))
    }

    func testIdentityDomain() {
        XCTAssertEqual(Domains.identityDomain(forItemUrl: "https://app.example.co.uk/login"), "example.co.uk")
        XCTAssertEqual(Domains.identityDomain(forItemUrl: "example.com"), "example.com")
        XCTAssertEqual(Domains.identityDomain(forItemUrl: "https://accounts.google.com"), "google.com")
        XCTAssertNil(Domains.identityDomain(forItemUrl: ""))
        XCTAssertNil(Domains.identityDomain(forItemUrl: nil))
        XCTAssertNil(Domains.identityDomain(forItemUrl: "not a url at all"))
    }
}
