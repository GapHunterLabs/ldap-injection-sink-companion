package dev.gaphunter.ldapinjectionsinkcompanion.detect

import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.JavaTokenType
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiExpression
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiLiteralExpression
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.PsiPolyadicExpression
import com.intellij.psi.PsiReferenceExpression
import com.intellij.psi.PsiVariable
import dev.gaphunter.ldapinjectionsinkcompanion.ldap.LdapFilterParser
import dev.gaphunter.ldapinjectionsinkcompanion.model.LdapSinkHit

/**
 * Finds `ctx.search(name, filterExpr, ...)` call sites (where `ctx`'s
 * declared type mentions `DirContext`/`LdapContext`) whose
 * `filterExpr` (the second argument) is built (same method, direct
 * reference or one-hop concatenation) from an HTTP endpoint parameter
 * -- CWE-90. Same "taint alone is the vulnerability, flagged
 * unconditionally" reasoning as this catalog's SpEL/XPath sink
 * finders: the attacker controls the substituted text's shape.
 *
 * The grammar's job here is the same noise-reduction role as in the
 * XPath plugin: the argument's static skeleton (tainted operand
 * replaced by a placeholder) must parse as a well-formed RFC 4515
 * filter before flagging.
 */
object JavaLdapInjectionSinkFinder {

    fun findAll(file: PsiFile): List<LdapSinkHit> {
        val hits = mutableListOf<LdapSinkHit>()
        file.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethod(method: PsiMethod) {
                super.visitMethod(method)
                if (!ControllerEndpointSignals.isEndpointMethod(method)) return
                hits += hitsForMethod(method)
            }
        })
        return hits
    }

    private fun hitsForMethod(method: PsiMethod): List<LdapSinkHit> {
        val body = method.body ?: return emptyList()
        val taintedNames = method.parameterList.parameters.map { it.name }.toSet()
        if (taintedNames.isEmpty()) return emptyList()

        val hits = mutableListOf<LdapSinkHit>()
        body.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(call: PsiMethodCallExpression) {
                super.visitMethodCallExpression(call)
                if (call.methodExpression.referenceName != "search") return
                if (!looksLikeDirContext(call.methodExpression.qualifierExpression)) return
                val argument = call.argumentList.expressions.getOrNull(1) ?: return

                val taintedName = firstTaintedReference(argument, taintedNames) ?: return

                // A BARE tainted reference (no concatenation at all) has no static
                // skeleton to validate -- the whole filter is attacker-controlled,
                // the single most dangerous shape, flagged unconditionally. The
                // grammar's noise-reduction role only applies when there's a real
                // static skeleton around the taint (the concatenation case below).
                if (argument !is PsiReferenceExpression) {
                    val skeleton = buildTaintSkeleton(argument) ?: return
                    if (LdapFilterParser.parse(skeleton) == null) return
                }

                val anchor = call.methodExpression.referenceNameElement ?: call.methodExpression
                hits += LdapSinkHit(anchor, taintedName)
            }
        })
        return hits
    }

    private fun firstTaintedReference(expression: PsiElement, taintedNames: Set<String>): String? {
        var found: String? = null
        expression.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitReferenceExpression(expr: PsiReferenceExpression) {
                if (found != null) return
                super.visitReferenceExpression(expr)
                val name = expr.referenceName
                if (name != null && name in taintedNames) found = name
            }
        })
        return found
    }

    private fun buildTaintSkeleton(expression: PsiExpression): String? = when (expression) {
        is PsiLiteralExpression -> (expression.value as? String) ?: PLACEHOLDER
        is PsiReferenceExpression -> PLACEHOLDER
        is PsiPolyadicExpression -> {
            if (expression.operationTokenType != JavaTokenType.PLUS) {
                null
            } else {
                expression.operands.joinToString("") { operand -> (operand as? PsiLiteralExpression)?.value as? String ?: PLACEHOLDER }
            }
        }
        else -> PLACEHOLDER
    }

    private const val PLACEHOLDER = "PLACEHOLDER"

    private fun looksLikeDirContext(qualifier: PsiExpression?): Boolean {
        val resolved = (qualifier as? PsiReferenceExpression)?.resolve() as? PsiVariable ?: return false
        val typeText = resolved.type.presentableText
        return typeText.contains("DirContext") || typeText.contains("LdapContext")
    }
}
