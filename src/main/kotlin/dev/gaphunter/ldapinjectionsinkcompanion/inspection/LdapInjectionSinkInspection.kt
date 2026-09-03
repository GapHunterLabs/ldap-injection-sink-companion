package dev.gaphunter.ldapinjectionsinkcompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.psi.PsiFile
import dev.gaphunter.ldapinjectionsinkcompanion.detect.JavaLdapInjectionSinkFinder
import dev.gaphunter.ldapinjectionsinkcompanion.model.LdapSinkHit
import dev.gaphunter.ldapinjectionsinkcompanion.review.ReviewPrompt

/** Flags a `DirContext.search(...)` call whose filter argument is tainted by an HTTP endpoint parameter -- CWE-90. See [JavaLdapInjectionSinkFinder]. */
class LdapInjectionSinkInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        if (file.text.length > MAX_FILE_LENGTH) return null

        val hits = JavaLdapInjectionSinkFinder.findAll(file)
        if (hits.isEmpty()) return null

        val problems = hits.map { hit ->
            manager.createProblemDescriptor(
                hit.anchor,
                messageFor(hit),
                isOnTheFly,
                emptyArray(),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
            )
        }

        val path = file.virtualFile?.path
        if (path != null) {
            for (hit in hits) {
                val lineNumber = file.viewProvider.document?.getLineNumber(hit.anchor.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber:${hit.taintedParameterName}")
            }
        }

        return problems.toTypedArray()
    }

    private fun messageFor(hit: LdapSinkHit): String =
        "LDAP filter built from endpoint parameter '${hit.taintedParameterName}' -- an attacker's raw input becomes " +
            "LDAP filter SOURCE TEXT re-parsed by the directory server (CWE-90)"
}
