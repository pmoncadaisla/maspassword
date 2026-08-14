package com.maspassword.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ItemDataTest {

    @Test
    fun `parses the exact JSON the web saveItem produces`() {
        val d = ItemData.fromJson(WebVectors.ITEM_JSON)
        assertEquals("login", d.type)
        assertEquals("Ejemplo S.A.", d.title)
        assertEquals("ana", d.username)
        assertEquals("s3cret!ñ€", d.password)
        assertEquals("https://app.example.co.uk/login", d.url)
        assertEquals("línea1\nlínea2", d.notes)
        assertEquals("JBSWY3DPEHPK3PXP", d.totpSecret)
        assertEquals(listOf("work", "ütf-8"), d.tags)
        assertTrue(d.favorite)
        assertEquals(listOf(CustomField("PIN", "1234", true)), d.customFields)
        assertEquals(listOf(Attachment("a.txt", "text/plain", 5L, "aGVsbG8=")), d.attachments)
        // Unknown fields (icon, pwChangedAt, ...) stay available through raw.
        assertEquals(WebVectors.ITEM_JSON, d.raw)
        assertTrue(d.isLogin)
    }

    @Test
    fun `minimal item defaults every field - like the web viewer`() {
        val d = ItemData.fromJson("""{"title":"Only title"}""")
        assertEquals("login", d.type) // web itemType(): unknown/absent -> login
        assertEquals("Only title", d.title)
        assertEquals("", d.username)
        assertEquals("", d.password)
        assertEquals("", d.url)
        assertEquals("", d.notes)
        assertEquals("", d.totpSecret)
        assertTrue(d.tags.isEmpty())
        assertFalse(d.favorite)
        assertTrue(d.customFields.isEmpty())
        assertTrue(d.attachments.isEmpty())
    }

    @Test
    fun `unknown type normalizes to login - known types survive`() {
        assertEquals("login", ItemData.fromJson("""{"type":"wat"}""").type)
        assertEquals("card", ItemData.fromJson("""{"type":"card"}""").type)
        assertEquals("note", ItemData.fromJson("""{"type":"note"}""").type)
        assertEquals("identity", ItemData.fromJson("""{"type":"identity"}""").type)
        assertFalse(ItemData.fromJson("""{"type":"note"}""").isLogin)
    }

    @Test
    fun `json nulls are treated as absent, not the string null`() {
        val d = ItemData.fromJson("""{"title":null,"username":null,"tags":null,"favorite":null}""")
        assertEquals("", d.title)
        assertEquals("", d.username)
        assertTrue(d.tags.isEmpty())
        assertFalse(d.favorite)
    }

    @Test
    fun `malformed entries inside arrays are skipped`() {
        val d = ItemData.fromJson(
            """{"tags":["a", null, "", "b"],"customFields":[{"label":"x"}, "junk", null]}""",
        )
        assertEquals(listOf("a", "b"), d.tags)
        assertEquals(listOf(CustomField("x", "", false)), d.customFields)
    }

    @Test
    fun `non-object input is rejected`() {
        assertThrows(IllegalArgumentException::class.java) { ItemData.fromJson("not json") }
        assertThrows(IllegalArgumentException::class.java) { ItemData.fromJson("[1,2]") }
        assertThrows(IllegalArgumentException::class.java) { ItemData.fromJson("") }
    }

    @Test
    fun `search matches title username url notes and tags - case-insensitive`() {
        val d = ItemData.fromJson(WebVectors.ITEM_JSON)
        assertTrue(d.matchesQuery(""))
        assertTrue(d.matchesQuery("ejemplo"))
        assertTrue(d.matchesQuery("ANA"))
        assertTrue(d.matchesQuery("example.co.uk"))
        assertTrue(d.matchesQuery("línea2"))
        assertTrue(d.matchesQuery("work"))
        assertFalse(d.matchesQuery("nothere"))
        assertFalse(d.matchesQuery("s3cret")) // passwords are NOT searched
    }
}
