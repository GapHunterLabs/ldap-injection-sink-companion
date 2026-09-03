package dev.gaphunter.ldapinjectionsinkcompanion.ldap

/**
 * Hand-rolled recursive-descent parser for RFC 4515 LDAP search
 * filters. A hybrid technique, deliberately: structure (`(`/`)`
 * nesting, `&`/`|`/`!` prefixes) is walked via real recursive parsing,
 * but a leaf item's value is captured as raw text between the
 * operator and the closing `)` -- an LDAP filter value can legally
 * contain almost any character (including a literal `*` wildcard),
 * so there's no fixed token grammar for it worth building for what
 * this plugin actually needs (confirming the filter's real STRUCTURE
 * parses, the same "grammar as skeleton-validation, not a security
 * gate" role this catalog's XPath grammar already plays).
 *
 * Returns null (never a partial/best-effort tree) on any malformed
 * input -- unbalanced parens, an empty filter list for `&`/`|`, `!`
 * with anything but exactly one operand, or a leaf with no real
 * operator.
 */
object LdapFilterParser {

    private val OPERATORS = listOf(">=", "<=", "~=", "=") // 2-char forms checked first

    fun parse(text: String): LdapFilterNode? {
        val trimmed = text.trim()
        if (trimmed.isEmpty() || trimmed.first() != '(') return null
        val closeIndex = findMatchingParen(trimmed, 0) ?: return null
        if (closeIndex != trimmed.length - 1) return null // trailing garbage after the outermost filter
        return parseFilter(trimmed, 0, closeIndex)
    }

    /** Parses the single filter whose own parens are at [openIndex]/[closeIndex] in [text]. */
    private fun parseFilter(text: String, openIndex: Int, closeIndex: Int): LdapFilterNode? {
        val innerStart = openIndex + 1
        if (innerStart >= closeIndex) return null

        return when (text[innerStart]) {
            '&' -> parseFilterList(text, innerStart + 1, closeIndex)?.let { LdapAndFilter(it) }
            '|' -> parseFilterList(text, innerStart + 1, closeIndex)?.let { LdapOrFilter(it) }
            '!' -> {
                val operands = parseFilterList(text, innerStart + 1, closeIndex) ?: return null
                if (operands.size != 1) null else LdapNotFilter(operands[0])
            }
            else -> parseItem(text.substring(innerStart, closeIndex))
        }
    }

    /** One or more consecutive `(...)` filters between [start] (inclusive) and [end] (exclusive, the enclosing `)`). */
    private fun parseFilterList(text: String, start: Int, end: Int): List<LdapFilterNode>? {
        val result = mutableListOf<LdapFilterNode>()
        var i = start
        while (i < end) {
            if (text[i].isWhitespace()) {
                i++
                continue
            }
            if (text[i] != '(') return null
            val close = findMatchingParen(text, i) ?: return null
            if (close > end) return null
            result += parseFilter(text, i, close) ?: return null
            i = close + 1
        }
        return result.ifEmpty { null }
    }

    private fun parseItem(text: String): LdapItemFilter? {
        for (operator in OPERATORS) {
            val index = text.indexOf(operator)
            if (index > 0) {
                val attribute = text.substring(0, index)
                val value = text.substring(index + operator.length)
                return LdapItemFilter(attribute, operator, value)
            }
        }
        return null
    }

    private fun findMatchingParen(text: String, openIndex: Int): Int? {
        if (text.getOrNull(openIndex) != '(') return null
        var depth = 0
        var i = openIndex
        while (i < text.length) {
            when (text[i]) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) return i
                }
            }
            i++
        }
        return null
    }
}
