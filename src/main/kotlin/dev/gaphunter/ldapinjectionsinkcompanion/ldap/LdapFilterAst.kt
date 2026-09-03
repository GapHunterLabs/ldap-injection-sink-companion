package dev.gaphunter.ldapinjectionsinkcompanion.ldap

/**
 * A hand-built AST for real LDAP search filter syntax (RFC 4515) --
 * the FOURTH full custom grammar in this catalog (after regex, SpEL,
 * and XPath). Structurally distinct from all three: LDAP filters are
 * fully PREFIX/Polish notation (`(&(a=1)(b=2))`, the operator comes
 * BEFORE its operands, all of them already parenthesized) with no
 * infix operators and no operator precedence to worry about at all --
 * a genuinely different parsing shape, not a variation on the
 * infix-with-postfix-steps grammars already in this catalog.
 */
sealed class LdapFilterNode

data class LdapAndFilter(val operands: List<LdapFilterNode>) : LdapFilterNode()
data class LdapOrFilter(val operands: List<LdapFilterNode>) : LdapFilterNode()
data class LdapNotFilter(val operand: LdapFilterNode) : LdapFilterNode()

/** `(attribute<operator>value)` -- a leaf filter item, e.g. `(uid=admin)`, `(age>=18)`. */
data class LdapItemFilter(val attribute: String, val operator: String, val value: String) : LdapFilterNode()
