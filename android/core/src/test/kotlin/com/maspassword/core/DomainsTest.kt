package com.maspassword.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of extension/domain.test.mjs plus the autofill-specific entry point.
 * Same anti-phishing guarantees as the Chrome extension.
 */
class DomainsTest {

    @Test
    fun `registrableDomain - same cases as the extension tests`() {
        assertEquals("google.com", Domains.registrableDomain("www.google.com"))
        assertEquals("google.com", Domains.registrableDomain("accounts.google.com"))
        assertEquals("bar.co.uk", Domains.registrableDomain("foo.bar.co.uk"))
        assertEquals("b.com.au", Domains.registrableDomain("a.b.com.au"))
        assertEquals("localhost", Domains.registrableDomain("localhost"))
        assertEquals("google.com", Domains.registrableDomain("GOOGLE.COM"))
        assertEquals("google.com", Domains.registrableDomain("google.com."))
        assertEquals("example.co.jp", Domains.registrableDomain("login.example.co.jp"))
        assertEquals("127.0.0.1", Domains.registrableDomain("127.0.0.1"))
        assertEquals("", Domains.registrableDomain(""))
        assertEquals("", Domains.registrableDomain(null))
    }

    @Test
    fun `registrableDomain - ip and edge hosts`() {
        assertEquals("[::1]", Domains.registrableDomain("[::1]"))
        assertEquals("intranet", Domains.registrableDomain("intranet"))
        assertEquals("co.uk", Domains.registrableDomain("www.co.uk")) // after www strip: 2 labels
        assertEquals("example.com", Domains.registrableDomain("www.www.example.com")) // single www strip
    }

    @Test
    fun `domainsMatch - true for same registrable domain`() {
        assertTrue(Domains.domainsMatch("https://accounts.google.com/signin", "https://www.google.com"))
        assertTrue(Domains.domainsMatch("https://app.example.co.uk/login", "https://example.co.uk"))
    }

    @Test
    fun `domainsMatch - anti-phishing cases are false`() {
        assertFalse(Domains.domainsMatch("https://evil-google.com", "https://google.com"))
        assertFalse(Domains.domainsMatch("https://paypal.com.attacker.com", "https://paypal.com"))
        assertFalse(Domains.domainsMatch("https://google.evil.com", "https://google.com"))
    }

    @Test
    fun `domainsMatch - fails closed on empty or invalid input`() {
        assertFalse(Domains.domainsMatch("", "https://google.com"))
        assertFalse(Domains.domainsMatch("not a url", "https://google.com"))
        assertFalse(Domains.domainsMatch("https://google.com", ""))
        assertFalse(Domains.domainsMatch(null, "https://google.com"))
    }

    @Test
    fun `autofillMatch - matches saved item to the page's web domain`() {
        assertTrue(Domains.autofillMatch("accounts.google.com", "https://www.google.com/login"))
        assertTrue(Domains.autofillMatch("app.example.co.uk", "https://example.co.uk"))
        // Item URLs saved without a scheme still match (item-side leniency).
        assertTrue(Domains.autofillMatch("www.example.com", "example.com"))
        assertTrue(Domains.autofillMatch("www.example.com", "example.com/login?next=1"))
    }

    @Test
    fun `autofillMatch - anti-phishing and fail-closed cases`() {
        assertFalse(Domains.autofillMatch("evil-google.com", "https://google.com"))
        assertFalse(Domains.autofillMatch("paypal.com.attacker.com", "https://paypal.com"))
        assertFalse(Domains.autofillMatch(null, "https://google.com"))        // native app: no webDomain
        assertFalse(Domains.autofillMatch("", "https://google.com"))
        assertFalse(Domains.autofillMatch("google.com", null))                 // item without URL
        assertFalse(Domains.autofillMatch("google.com", ""))
        assertFalse(Domains.autofillMatch("google.com/phish", "https://google.com")) // not a bare host
        assertFalse(Domains.autofillMatch("user@google.com", "https://google.com"))
        assertFalse(Domains.autofillMatch("google.com", "not a url at all ::"))
    }

    @Test
    fun `hostnameOfItemUrl - lenient only when no scheme was given`() {
        assertEquals("example.com", Domains.hostnameOfItemUrl("https://example.com/x"))
        assertEquals("example.com", Domains.hostnameOfItemUrl("example.com"))
        assertEquals("example.com", Domains.hostnameOfItemUrl("example.com/path"))
        assertEquals("", Domains.hostnameOfItemUrl("javascript://alert(1)"))
        assertEquals("", Domains.hostnameOfItemUrl(""))
        assertEquals("", Domains.hostnameOfItemUrl(null))
    }
}
