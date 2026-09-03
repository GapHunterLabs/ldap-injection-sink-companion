package dev.gaphunter.ldapinjectionsinkcompanion.ldap

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LdapFilterParserTest {

    @Test
    fun `a simple equality item parses`() {
        val node = LdapFilterParser.parse("(uid=admin)") as LdapItemFilter
        assertEquals("uid", node.attribute)
        assertEquals("=", node.operator)
        assertEquals("admin", node.value)
    }

    @Test
    fun `an AND of two items parses`() {
        val node = LdapFilterParser.parse("(&(uid=admin)(objectClass=person))") as LdapAndFilter
        assertEquals(2, node.operands.size)
        assertEquals("uid", (node.operands[0] as LdapItemFilter).attribute)
        assertEquals("objectClass", (node.operands[1] as LdapItemFilter).attribute)
    }

    @Test
    fun `an OR of two items parses`() {
        val node = LdapFilterParser.parse("(|(uid=admin)(uid=root))") as LdapOrFilter
        assertEquals(2, node.operands.size)
    }

    @Test
    fun `a NOT with exactly one operand parses`() {
        val node = LdapFilterParser.parse("(!(uid=admin))") as LdapNotFilter
        assertEquals("uid", (node.operand as LdapItemFilter).attribute)
    }

    @Test
    fun `nested boolean operators parse, e_g_ a classic bypass payload shape`() {
        // A real-world LDAP injection bypass shape: `admin)(&))` style
        // payloads restructure the filter -- this test just confirms a
        // NESTED, multi-level filter of that general shape parses at all.
        val node = LdapFilterParser.parse("(&(uid=admin)(|(objectClass=person)(objectClass=admin)))")
        assertNotNull(node)
        assertTrue(node is LdapAndFilter)
    }

    @Test
    fun `relational operators greater-equal and less-equal parse`() {
        assertEquals(">=", (LdapFilterParser.parse("(age>=18)") as LdapItemFilter).operator)
        assertEquals("<=", (LdapFilterParser.parse("(age<=65)") as LdapItemFilter).operator)
    }

    @Test
    fun `a wildcard value is treated as ordinary text and still parses`() {
        val node = LdapFilterParser.parse("(cn=*admin*)") as LdapItemFilter
        assertEquals("*admin*", node.value)
    }

    @Test
    fun `unbalanced parens fail to parse`() {
        assertNull(LdapFilterParser.parse("(uid=admin"))
    }

    @Test
    fun `an AND with no operands fails to parse`() {
        assertNull(LdapFilterParser.parse("(&)"))
    }

    @Test
    fun `a NOT with more than one operand fails to parse`() {
        assertNull(LdapFilterParser.parse("(!(uid=admin)(uid=root))"))
    }

    @Test
    fun `trailing garbage after the outermost filter fails to parse`() {
        assertNull(LdapFilterParser.parse("(uid=admin) garbage"))
    }

    @Test
    fun `text not starting with a parenthesis fails to parse`() {
        assertNull(LdapFilterParser.parse("uid=admin"))
    }
}
