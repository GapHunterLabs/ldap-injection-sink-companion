package dev.gaphunter.ldapinjectionsinkcompanion.model

import com.intellij.psi.PsiElement

/** A confirmed LDAP injection sink: [taintedParameterName] flows (same method, direct reference or one-hop concatenation) into a `DirContext.search(...)` filter argument whose static skeleton parses as a well-formed RFC 4515 filter. */
data class LdapSinkHit(val anchor: PsiElement, val taintedParameterName: String)
