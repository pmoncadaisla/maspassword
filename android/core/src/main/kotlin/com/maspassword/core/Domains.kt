package com.maspassword.core

import java.net.URI
import java.net.URISyntaxException

/**
 * Registrable-domain (eTLD+1) matching, ported from `extension/domain.js`.
 *
 * Anti-phishing invariant (same as the Chrome extension): a saved login is
 * offered for a page ONLY when both sides reduce to the same registrable
 * domain. Never substring comparison. Any unparseable or empty input matches
 * nothing (fail closed). `evil-google.com`, `paypal.com.attacker.com` and
 * `google.evil.com` do NOT match `google.com` / `paypal.com`.
 *
 * One deliberate divergence, item-side only: saved item URLs without a scheme
 * ("example.com/login") are retried as https:// before giving up, because the
 * SAVED url is user data, not attacker-controlled input — the page side
 * (autofill webDomain / tab URL) stays strict.
 */
object Domains {

    // Same embedded set as extension/domain.js. Not exhaustive: covers common
    // multi-part public suffixes; everything else uses the last-two-labels rule.
    private val MULTI_PART_SUFFIXES = setOf(
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
    )

    private val IPV4_RE = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    /** Bare IP literal (v4, or v6 with/without brackets)? */
    fun isIpAddress(host: String): Boolean {
        if (IPV4_RE.matches(host)) return true
        if (host.startsWith("[") && host.endsWith("]")) return true
        if (host.contains(':')) return true
        return false
    }

    /**
     * Reduce a hostname to its registrable domain (eTLD+1). Lowercases,
     * strips a trailing dot and a single leading "www.". IPs / localhost /
     * single-label hosts are returned unchanged. Empty input -> "".
     */
    fun registrableDomain(hostname: String?): String {
        if (hostname.isNullOrEmpty()) return ""
        var host = hostname.trim().lowercase()
        host = host.removeSuffix(".")
        host = host.removePrefix("www.")
        if (host.isEmpty()) return ""

        if (host == "localhost") return host
        if (isIpAddress(host)) return host

        val labels = host.split(".")
        if (labels.size <= 2) return host

        val lastTwo = labels.takeLast(2).joinToString(".")
        if (lastTwo in MULTI_PART_SUFFIXES) {
            // Public suffix is two labels (e.g. co.uk) -> eTLD+1 is 3 labels.
            return labels.takeLast(3).joinToString(".")
        }
        return lastTwo
    }

    /** Hostname of an absolute URL, or "" when unparseable (fail closed). */
    fun hostnameOf(url: String?): String {
        if (url.isNullOrBlank()) return ""
        return try {
            URI(url.trim()).host ?: ""
        } catch (e: URISyntaxException) {
            ""
        }
    }

    /**
     * Hostname of a SAVED item URL. First tries the strict parse; if that
     * yields nothing and the value has no scheme, retries with "https://".
     */
    fun hostnameOfItemUrl(itemUrl: String?): String {
        if (itemUrl.isNullOrBlank()) return ""
        val strict = hostnameOf(itemUrl)
        if (strict.isNotEmpty()) return strict
        val trimmed = itemUrl.trim()
        if (trimmed.contains("://")) return "" // had a scheme and still failed
        return hostnameOf("https://$trimmed")
    }

    /** True iff both URLs parse AND share a registrable domain (fail closed). */
    fun domainsMatch(urlA: String?, urlB: String?): Boolean {
        val hostA = hostnameOf(urlA)
        val hostB = hostnameOf(urlB)
        if (hostA.isEmpty() || hostB.isEmpty()) return false
        val regA = registrableDomain(hostA)
        val regB = registrableDomain(hostB)
        if (regA.isEmpty() || regB.isEmpty()) return false
        return regA == regB
    }

    /**
     * Autofill matching: [webDomain] is the HOSTNAME the OS reports for the
     * page being filled (`ViewNode.webDomain`); [itemUrl] is the saved item's
     * URL. Returns false whenever either side is missing or malformed:
     *
     *  - No webDomain (native app, no verified browser domain) -> NO match.
     *    Package names are not matched against saved URLs — a sideloaded app
     *    can claim any package name, so that path stays closed; the user can
     *    still pick an item manually.
     *  - webDomain containing separators/spaces (not a bare host) -> no match.
     */
    fun autofillMatch(webDomain: String?, itemUrl: String?): Boolean {
        val host = webDomain?.trim()?.lowercase() ?: return false
        if (host.isEmpty() || host.any { it == '/' || it == '\\' || it == '@' || it.isWhitespace() }) return false
        val itemHost = hostnameOfItemUrl(itemUrl)
        if (itemHost.isEmpty()) return false
        val regPage = registrableDomain(host)
        val regItem = registrableDomain(itemHost)
        if (regPage.isEmpty() || regItem.isEmpty()) return false
        return regPage == regItem
    }
}
